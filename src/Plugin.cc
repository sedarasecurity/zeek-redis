#include "Plugin.h"
#include "RedisWriter.h"

namespace plugin { namespace Sedara_Redis { Plugin plugin; }} // namespace plugin

using namespace plugin::Sedara_Redis;

zeek::plugin::Configuration Plugin::Configure() {
  AddComponent(new zeek::logging::Component(
      "RedisWriter", ::logging::writer::RedisWriter::Instantiate));

  zeek::plugin::Configuration config;
  config.name = "Sedara::Redis";
  config.description = "Writes logs to Redis";
  config.version.major = 0;
  config.version.minor = 1;
  return config;
}
