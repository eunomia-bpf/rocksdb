//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#ifndef ROCKSDB_LITE

#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "db/db_impl/db_impl.h"
#include "port/port.h"
#include "rocksdb/db.h"
#include "rocksdb/env.h"
#include "test_util/sync_point.h"
#include "test_util/testharness.h"
#include "util/cast_util.h"
#include "util/string_util.h"

namespace ROCKSDB_NAMESPACE {

class CompactFilesTest : public testing::Test {
 public:
  CompactFilesTest() {
    env_ = Env::Default();
    db_name_ = test::PerThreadDBPath("compact_files_test");
  }

  std::string db_name_;
  Env* env_;
};

// A class which remembers the name of each flushed file.
class FlushedFileCollector : public EventListener {
 public:
  FlushedFileCollector() {}
  ~FlushedFileCollector() override {}

  void OnFlushCompleted(DB* /*db*/, const FlushJobInfo& info) override {
    std::lock_guard<std::mutex> lock(mutex_);
    flushed_files_.push_back(info.file_path);
  }

  std::vector<std::string> GetFlushedFiles() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (auto fname : flushed_files_) {
      result.push_back(fname);
    }
    return result;
  }
  void ClearFlushedFiles() {
    std::lock_guard<std::mutex> lock(mutex_);
    flushed_files_.clear();
  }

 private:
  std::vector<std::string> flushed_files_;
  std::mutex mutex_;
};

TEST_F(CompactFilesTest, L0ConflictsFiles) {
  Options options;
  // to trigger compaction more easily
  const int kWriteBufferSize = 10000;
  const int kLevel0Trigger = 2;
  options.create_if_missing = true;
  options.compaction_style = kCompactionStyleLevel;
  // Small slowdown and stop trigger for experimental purpose.
  options.level0_slowdown_writes_trigger = 20;
  options.level0_stop_writes_trigger = 20;
  options.level0_stop_writes_trigger = 20;
  options.write_buffer_size = kWriteBufferSize;
  options.level0_file_num_compaction_trigger = kLevel0Trigger;
  options.compression = kNoCompression;

  DB* db = nullptr;
  ASSERT_OK(DestroyDB(db_name_, options));
  Status s = DB::Open(options, db_name_, &db);
  assert(s.ok());
  assert(db);

  ROCKSDB_NAMESPACE::SyncPoint::GetInstance()->LoadDependency({
      {"CompactFilesImpl:0", "BackgroundCallCompaction:0"},
      {"BackgroundCallCompaction:1", "CompactFilesImpl:1"},
  });
  ROCKSDB_NAMESPACE::SyncPoint::GetInstance()->EnableProcessing();

  // create couple files
  // Background compaction starts and waits in BackgroundCallCompaction:0
  for (int i = 0; i < kLevel0Trigger * 4; ++i) {
    ASSERT_OK(db->Put(WriteOptions(), std::to_string(i), ""));
    ASSERT_OK(db->Put(WriteOptions(), std::to_string(100 - i), ""));
    ASSERT_OK(db->Flush(FlushOptions()));
  }

  ROCKSDB_NAMESPACE::ColumnFamilyMetaData meta;
  db->GetColumnFamilyMetaData(&meta);
  std::string file1;
  for (auto& file : meta.levels[0].files) {
    ASSERT_EQ(0, meta.levels[0].level);
    if (file1 == "") {
      file1 = file.db_path + "/" + file.name;
    } else {
      std::string file2 = file.db_path + "/" + file.name;
      // Another thread starts a compact files and creates an L0 compaction
      // The background compaction then notices that there is an L0 compaction
      // already in progress and doesn't do an L0 compaction
      // Once the background compaction finishes, the compact files finishes
      ASSERT_OK(db->CompactFiles(ROCKSDB_NAMESPACE::CompactionOptions(),
                                 {file1, file2}, 0));
      break;
    }
  }
  ROCKSDB_NAMESPACE::SyncPoint::GetInstance()->DisableProcessing();
  delete db;
}

}  // namespace ROCKSDB_NAMESPACE

int main(int argc, char** argv) {
  ROCKSDB_NAMESPACE::port::InstallStackTraceHandler();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#else
#include <stdio.h>

int main(int /*argc*/, char** /*argv*/) {
  fprintf(stderr,
          "SKIPPED as DBImpl::CompactFiles is not supported in ROCKSDB_LITE\n");
  return 0;
}

#endif  // !ROCKSDB_LITE
