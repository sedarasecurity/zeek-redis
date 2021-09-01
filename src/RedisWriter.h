#ifndef LOGGING_WRITER_REDIS_H
#define LOGGING_WRITER_REDIS_H
#include <sw/redis++/redis++.h>

#include <zeek/Desc.h>
#include <zeek/logging/WriterBackend.h>
#include <zeek/threading/Formatter.h>
#include <zeek/threading/formatters/Ascii.h>
#include <zeek/threading/formatters/JSON.h>
#include <zeek/zeek-bif.h>

#include "redis.bif.h"
#include <string>

namespace logging {
namespace writer {

/**
 * A logging writer that sends data to a Redis server.
 */
class RedisWriter : public zeek::logging::WriterBackend {
public:
  explicit RedisWriter(zeek::logging::WriterFrontend *frontend);
  ~RedisWriter();

  static zeek::logging::WriterBackend *
  Instantiate(zeek::logging::WriterFrontend *frontend) {
    return new RedisWriter(frontend);
  }

protected:
  virtual bool DoInit(const zeek::logging::WriterBackend::WriterInfo &info,
                      int num_fields,
                      const zeek::threading::Field *const *fields);
  virtual bool DoWrite(int num_fields,
                       const zeek::threading::Field *const *fields,
                       zeek::threading::Value **vals);
  virtual bool DoSetBuf(bool enabled);
  virtual bool DoRotate(const char *rotated_path, double open, double close,
                        bool terminating);
  virtual bool DoFlush(double network_time);
  virtual bool DoFinish(double network_time);
  virtual bool DoHeartbeat(double network_time, double current_time);

private:
  std::string LookupParam(const WriterInfo &info, const std::string name) const;
  std::tuple<bool, std::string, int>
  CreateParams(const zeek::threading::Value *val);
  bool uid_to_cid_mapping;
  std::string json_timestamps;
  bool mocking;
  bool debugging;
  std::string redis_host;
  std::string redis_password;
  std::string default_uid_to_cid_mapping;
  int redis_port;
  int redis_db;
  int pool_size;
  int pool_connection_lifetime;
  zeek::threading::Formatter *formatter;
  std::unique_ptr<sw::redis::Redis> redis_client;
  std::unique_ptr<zeek::threading::formatter::Ascii> io;
};

} // namespace writer
} // namespace logging

#endif
