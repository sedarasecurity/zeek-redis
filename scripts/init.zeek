
#event zeek_init()
#{
#    # Add a new filter to the Conn::LOG stream that logs only
#    # uid and community id
#    local filter: Log::Filter = [$name="uid_to_cid_mapping", $path="conn",
#                                $writer=Log::WRITER_REDIS, $include=set("uid", "community_id"),
#                                $config=table(["uid_to_cid_mapping"]="T")];
#    Log::add_filter(Conn::LOG, filter);
#}
