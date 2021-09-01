#doc-common-start
module Redis;

export {
# doc-options-start
    const json_timestamps: JSON::TimestampFormat = JSON::TS_EPOCH &redef;

    ## Enable debug mode.
    const debug: bool = F &redef;

    ## Enable mock.
    const mock: bool = F &redef;

    ## Redis hostname or IP address.
    const redis_host: string = "127.0.0.1" &redef;

    ## Port to connect to redis instance on
    const redis_port: count = 6379 &redef;

    const redis_db: count = 1 &redef;

    const redis_password: string = "" &redef;

    # enable storing the community id to Zeek UID mappings in Redis
    const uid_to_cid_mapping: bool = T &redef;

    const pool_size: count = 3 &redef;

    const pool_connection_lifetime: count = 10 &redef;
# doc-options-end
}