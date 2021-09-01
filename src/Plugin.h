#ifndef BRO_PLUGIN_SEDARA_REDIS
#define BRO_PLUGIN_SEDARA_REDIS

#include <plugin/Plugin.h>

namespace plugin {
  namespace Sedara_Redis {

    class Plugin : public zeek::plugin::Plugin
    {
    protected:
      // Overridden from plugin::Plugin.
      virtual zeek::plugin::Configuration Configure();
    };

    extern Plugin plugin;
  }
}

#endif
