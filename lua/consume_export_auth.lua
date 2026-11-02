-- KEYS[1] = fed:export:{ticket_nonce_hex}
-- KEYS[2] = auth:key:{target_dc}:{auth_key_id}
-- ARGV[1] = expected_target_dc
-- ARGV[2] = expected_user_id
-- ARGV[3] = target_auth_key_id

local ticket = redis.call('HMGET', KEYS[1], 'user_id', 'home_dc', 'target_dc', 'dc_epoch', 'consumed_by')
if not ticket[1] then
    return {0, 'TICKET_EXPIRED_OR_UNKNOWN', 0, 0}
end
if ticket[1] ~= ARGV[2] or ticket[3] ~= ARGV[1] then
    return {0, 'TICKET_MISMATCH', 0, 0}
end
if ticket[5] and ticket[5] ~= '' and ticket[5] ~= ARGV[3] then
    return {0, 'TICKET_ALREADY_USED', 0, 0}
end

redis.call('HSET', KEYS[1], 'consumed_by', ARGV[3])
redis.call('PEXPIRE', KEYS[1], 15000)
redis.call('HMSET', KEYS[2],
    'user_id', ticket[1],
    'home_dc', ticket[2],
    'dc_epoch', ticket[4],
    'binding_mode', '2'
)
return {1, 'OK', tonumber(ticket[2]), tonumber(ticket[4])}
