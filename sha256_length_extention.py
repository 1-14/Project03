from sha256 import *
from timeit import default_timer as timer


#该函数将消息转换为字节数组，并在末尾添加填充字节，直到满足填充规则。
#最后，它将消息的长度（以比特为单位）追加到填充后的消息末尾。
def sha256_padding(M, key_length):
    if isinstance(M, str):
        M = bytearray(M, 'ascii')
    elif isinstance(M, bytes):
        M = bytearray(M)
    elif not isinstance(M, bytearray):
        raise TypeError

    length = (len(M) + key_length) * 8
    M.append(0x80)
    while ((len(M) + key_length) * 8 + 64) % 512 != 0:
        M.append(0x00)

    M += length.to_bytes(8, 'big')

    assert ((len(M) + key_length) * 8) % 512 == 0, \
        "Padding did not complete properly!"

    return M

#将原始哈希值转换为内部状态数组。
def reverse_internal_state(h):
    res = [0] * 8
    res[0] = int(h[0:8], 16)
    res[1] = int(h[8:16], 16)
    res[2] = int(h[16:24], 16)
    res[3] = int(h[24:32], 16)
    res[4] = int(h[32:40], 16)
    res[5] = int(h[40:48], 16)
    res[6] = int(h[48:56], 16)
    res[7] = int(h[56:64], 16)
    return res

def length_extansion_attack(Original_message, Original_hash, keylen, Forge_message):
    state = reverse_internal_state(Original_hash)
    Original_message_padded = sha256_padding(Original_message, keylen)
    Forge_hash = Sha256(Forge_message, state, init_length=len(Original_message_padded) + keylen).hex()
    _Forge_message = Original_message_padded + bytearray(Forge_message, 'ascii')

    return _Forge_message, Forge_hash


if __name__ == '__main__':
    key = 'lyb'
    key_hash = base64.b16decode(key.encode().hex(), casefold=True)
    msg = '202100180118'
    h = sha256()
    h.update(key_hash)
    h.update(msg.encode())
    h = h.hexdigest()
    msg_append = '20230704'
    tic = timer()
    msg_extend, hash_attack = length_extansion_attack(msg, h, len(key), msg_append)
    toc = timer()
    hash_extend = sha256(key_hash + sha256_padding(msg, len(key)) + bytearray(msg_append, 'ascii')).hexdigest()
    print("原始消息:", msg)
    print("附加消息:", msg_append)
    print("构造的hash值:", hash_attack)
    print("新消息的hash值:", hash_extend)
    if hash_attack == hash_extend:
        print("攻击成功！")
        print(toc - tic,"s")
    else:
        print("攻击失败")
        print(toc - tic,"s")
