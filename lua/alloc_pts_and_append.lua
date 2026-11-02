-- KEYS[1] = pts:seq:{dc}:{user_id}
-- KEYS[2] = pts:ring:{dc}:{user_id}
-- ARGV[1] = pts_count (integer >= 1)
-- ARGV[2] = serialized_pts_envelope
-- ARGV[3] = ring_max_len (default 2048)
-- ARGV[4] = ttl_seconds (default 86400)

local delta = tonumber(ARGV[1])
local new_pts = redis.call('INCRBY', KEYS[1], delta)
redis.call('ZADD', KEYS[2], new_pts, ARGV[2])

local card = redis.call('ZCARD', KEYS[2])
local max_len = tonumber(ARGV[3])
if card > max_len then
    redis.call('ZREMRANGEBYRANK', KEYS[2], 0, card - max_len - 1)
end
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
return new_pts
