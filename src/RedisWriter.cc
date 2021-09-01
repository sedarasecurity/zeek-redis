#include "RedisWriter.h"
#include "threading/SerialTypes.h"
#include <cstring>
#include <errno.h>
#include <map>
#include <regex>
#include <string>
#include "zeek-config.h"
#include <vector>

using namespace logging;
using namespace writer;
using zeek::threading::Field;
using zeek::threading::Value;

// The Constructor is called once for each log filter that uses this log writer.
RedisWriter::RedisWriter(zeek::logging::WriterFrontend *frontend) : zeek::logging::WriterBackend(frontend) {
  io = std::unique_ptr<zeek::threading::formatter::Ascii>(
      new zeek::threading::formatter::Ascii(
          this, zeek::threading::formatter::Ascii::SeparatorInfo()));
  /**
   * We need thread-local copies of all user-defined settings coming from zeek
   * scripting land.  accessing these is not thread-safe and 'DoInit' is
   * potentially accessed from multiple threads.
   */

  debugging = zeek::BifConst::Redis::debug;
  mocking = zeek::BifConst::Redis::mock;
  uid_to_cid_mapping = zeek::BifConst::Redis::uid_to_cid_mapping;
  redis_host.assign((const char *)zeek::BifConst::Redis::redis_host->Bytes(),
                    zeek::BifConst::Redis::redis_host->Len());
  redis_port = zeek::BifConst::Redis::redis_port;
  redis_db = zeek::BifConst::Redis::redis_db;
  redis_password.assign((const char *)zeek::BifConst::Redis::redis_password->Bytes(),
                    zeek::BifConst::Redis::redis_password->Len());
  pool_size = zeek::BifConst::Redis::pool_size;
  pool_connection_lifetime = zeek::BifConst::Redis::pool_connection_lifetime;

  // json_timestamps
  zeek::ODesc tsfmt;
  zeek::BifConst::Redis::json_timestamps->Describe(&tsfmt);
  json_timestamps.assign((const char *)tsfmt.Bytes(), tsfmt.Len());
}

RedisWriter::~RedisWriter() {
  // Cleanup must happen in DoFinish, not in the destructor
}

std::string RedisWriter::LookupParam(const WriterInfo& info, const std::string name) const
{
	std::map<const char*, const char*>::const_iterator it = info.config.find(name.c_str());
	if ( it == info.config.end() )
		return std::string();
	else
		return it->second;
	}

/**
 * DoInit is called once for each call to the constructor, but in a separate
 * thread
 */
bool RedisWriter::DoInit(const WriterInfo &info, int num_fields,
                         const zeek::threading::Field *const *fields) {
  // TimeFormat object, default to TS_EPOCH
  zeek::threading::formatter::JSON::TimeFormat tf =
      zeek::threading::formatter::JSON::TS_EPOCH;

  std::string uid_to_cid_mapping_override = LookupParam(info, "uid_to_cid_mapping");
  if (!uid_to_cid_mapping_override.empty() )
  {
    // default_uid_to_cid_mapping.assign(
    //     (const char*) uid_to_cid_mapping_override->Bytes(),
    //     uid_to_cid_mapping_override->Len()
    //                         );
    if(uid_to_cid_mapping_override == "T") {
      uid_to_cid_mapping = true;
    } else {
      uid_to_cid_mapping = false;
    }
  }

  /**
   * Format the timestamps
   * NOTE: This string comparision implementation is currently the necessary
   * way to do it, as there isn't a way to pass the Zeek enum into C++ enum.
   * This makes the user interface consistent with the existing Zeek Logging
   * configuration for the ASCII log output.
   */
  if (strcmp(json_timestamps.c_str(), "JSON::TS_EPOCH") == 0) {
    tf = zeek::threading::formatter::JSON::TS_EPOCH;
  } else if (strcmp(json_timestamps.c_str(), "JSON::TS_MILLIS") == 0) {
    tf = zeek::threading::formatter::JSON::TS_MILLIS;
  } else if (strcmp(json_timestamps.c_str(), "JSON::TS_ISO8601") == 0) {
    tf = zeek::threading::formatter::JSON::TS_ISO8601;
  } else {
    Error(Fmt("RedisWriter::DoInit: Invalid JSON timestamp format %s",
              json_timestamps.c_str()));
    return false;
  }


  // initialize the formatter
  // if (BifConst::Redis::tag_json) {
  //   formatter = new zeek::threading::formatter::TaggedJSON(info.path, this, tf);
  // } else {
  formatter = new zeek::threading::formatter::JSON(this, tf);
  // }

  // is debug enabled
  // std::string debug;
  // debug.assign((const char *)zeek::BifConst::Redis::debug->Bytes(),
  //              zeek::BifConst::Redis::debug->Len());
  // bool is_debug(!debug.empty());
  bool is_debug;
  is_debug = debugging;
  if (is_debug) {
    MsgThread::Info(Fmt("Debug is turned on"));
  }

  // redis global configuration
  sw::redis::ConnectionOptions connection_options;

  connection_options.host = redis_host;
  connection_options.port = redis_port;
  connection_options.password = redis_password;
  connection_options.db = redis_db;
  sw::redis::ConnectionPoolOptions pool_options;

  pool_options.size = pool_size;
  pool_options.wait_timeout = std::chrono::milliseconds(100);

  pool_options.connection_lifetime = std::chrono::minutes(pool_connection_lifetime);

  if (!mocking) {
    // create redis client
    redis_client = std::make_unique<sw::redis::Redis>(connection_options, pool_options);
    if (is_debug) {
      MsgThread::Info(Fmt("Successfully connected to Redis instance."));
    }
  }
  return true;
}

/**
 * Writer-specific method called just before the threading system is
 * going to shutdown. It is assumed that once this messages returns,
 * the thread can be safely terminated. As such, all resources created must be
 * removed here.
 */
bool RedisWriter::DoFinish(double network_time) {
  return true;
}

std::tuple<bool, std::string, int> RedisWriter::CreateParams(const Value* val)
	{
	static std::regex curly_re("\\\\|\"");

	if ( ! val->present )
		return std::make_tuple(false, std::string(), 0);

	std::string retval;
	int retlength = 0;

	switch ( val->type ) {

	case zeek::TYPE_BOOL:
		retval = val->val.int_val ? "T" : "F";
		break;

	case zeek::TYPE_INT:
		retval = std::to_string(val->val.int_val);
		break;

	case zeek::TYPE_COUNT:
		retval = std::to_string(val->val.uint_val);
		break;

	case zeek::TYPE_PORT:
		retval = std::to_string(val->val.port_val.port);
		break;

	case zeek::TYPE_SUBNET:
		retval = io->Render(val->val.subnet_val);
		break;

	case zeek::TYPE_ADDR:
		retval = io->Render(val->val.addr_val);
		break;

	case zeek::TYPE_TIME:
	case zeek::TYPE_INTERVAL:
	case zeek::TYPE_DOUBLE:
		retval = std::to_string(val->val.double_val);
		break;

	case zeek::TYPE_ENUM:
	case zeek::TYPE_STRING:
	case zeek::TYPE_FILE:
	case zeek::TYPE_FUNC:
		retval = std::string(val->val.string_val.data, val->val.string_val.length);
		break;

	case zeek::TYPE_TABLE:
	case zeek::TYPE_VECTOR:
		{
		bro_int_t size;
		Value** vals;

		std::string out("{");
		retlength = 1;

		if ( val->type == zeek::TYPE_TABLE )
			{
			size = val->val.set_val.size;
			vals = val->val.set_val.vals;
			}
		else
			{
			size = val->val.vector_val.size;
			vals = val->val.vector_val.vals;
			}

		if ( ! size )
			return std::make_tuple(false, std::string(), 0);

		for ( int i = 0; i < size; ++i )
			{
			if ( i != 0 )
				out += ", ";

			auto res = CreateParams(vals[i]);
			if ( std::get<0>(res) == false )
				{
				out += "NULL";
				continue;
				}

			std::string resstr = std::get<1>(res);
			zeek::TypeTag type = vals[i]->type;
			// for all numeric types, we do not need escaping
			if ( type == zeek::TYPE_BOOL || type == zeek::TYPE_INT || type == zeek::TYPE_COUNT ||
					type == zeek::TYPE_PORT || type == zeek::TYPE_TIME ||
					type == zeek::TYPE_INTERVAL || type == zeek::TYPE_DOUBLE )
				out += resstr;
			else
				{
				std::string escaped = std::regex_replace(resstr, curly_re, "\\$&");
				out += "\"" + escaped + "\"";
				retlength += 2+escaped.length();
				}
			}

		out += "}";
		retlength += 1;
		retval = out;
		break;
		}

	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return std::make_tuple(false, std::string(), 0);
	}

	if ( retlength == 0 )
		retlength = retval.length();

	return std::make_tuple(true, retval, retlength);
	}

/**
 * Writer-specific output method implementing recording of one log
 * entry.
 */
bool RedisWriter::DoWrite(int num_fields, const zeek::threading::Field *const *fields,
                          zeek::threading::Value **vals) {
  if (mocking) {
    return true;
  }
  std::vector<std::tuple<bool, std::string, int>>
      params; // vector in which we compile the string representation of
              // characters

  zeek::ODesc buff;
  buff.Clear();

  MsgThread::Info(Fmt("num_fields: %0d", num_fields));
  for (int i = 0; i < num_fields; ++i)
    // MsgThread::Info(Fmt("Val: %s", vals[i]));
    params.push_back(CreateParams(vals[i]));

  if (uid_to_cid_mapping) {
    // std::cout << std::get<1>(params[0]) << std::endl;
    // std::cout << std::get<1>(params[1]) << std::endl;
    redis_client->lpush(std::get<1>(params[1]).c_str(), std::get<1>(params[0]).c_str());
    // for(auto &i: params ) {
    //   std::cout << std::get<0>(i) << std::endl;
    //   std::cout << std::get<1>(i) << std::endl;
    //   std::cout << std::get<2>(i) << std::endl;
    // }
    return true;
  }

  // format the log entry
  formatter->Describe(&buff, num_fields, fields, vals);
  const char *raw = (const char *)buff.Bytes();
  // send the formatted log entry to redis
  std::string entry = raw;
  redis_client->lpush("zeek", entry);
  return true;
}

/**
 * Writer-specific method implementing a change of the buffering
 * state.	If buffering is disabled, the writer should attempt to
 * write out information as quickly as possible even if doing so may
 * have a performance impact. If enabled (which is the default), it
 * may buffer data as helpful and write it out later in a way
 * optimized for performance. The current buffering state can be
 * queried via IsBuf().
 */
bool RedisWriter::DoSetBuf(bool enabled) {
  // no change in behavior
  return true;
}

/**
 * Writer-specific method implementing flushing of its output.	A writer
 * implementation must override this method but it can just
 * ignore calls if flushing doesn't align with its semantics.
 */
bool RedisWriter::DoFlush(double network_time) {
  // no change in behavior
  return true;
}

/**
 * Writer-specific method implementing log rotation.	Most directly
 * this only applies to writers writing into files, which should then
 * close the current file and open a new one.	However, a writer may
 * also trigger other apppropiate actions if semantics are similar.
 * Once rotation has finished, the implementation *must* call
 * FinishedRotation() to signal the log manager that potential
 * postprocessors can now run.
 */
bool RedisWriter::DoRotate(const char *rotated_path, double open, double close,
                           bool terminating) {
  // no need to perform log rotation
  FinishedRotation();
  return true;
}

/**
 * Triggered by regular heartbeat messages from the main thread.
 */
bool RedisWriter::DoHeartbeat(double network_time, double current_time) {
  // no change in behavior
  return true;
}
