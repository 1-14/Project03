#长度扩展攻击
from numpy import number
import SM3
import random
from timeit import default_timer as timer

#随机生成一个消息m
m = random.randrange(1000,10000)
#SM3文件中的函数，将十六进制字符串转换为十六进制数
m = SM3.AsToByte(hex(m))
#生成m的哈希值Hash1
Hash1  = SM3.SM3(m)
#生成m的填充
pad_m = SM3.Pad(m)
pad_m_len = len(pad_m)
#扩展以后的消息总长度
m_len =len(m)

_m = '616263'#abc

def length_extend_attack(_m,length_old):
    New_iv = []
    for i in range(8):
        New_iv.append(int(Hash1[i*8:i*8+8],16))
    #将原mssage的hash结果进行分组作为新的iv值
    length = hex((length_old+len(_m))*4)[2:]
    #计算出加上m’后的消息总长度
    length = (16-len(length))*'0' + length
    #最后填充的消息的长度
    _m = _m + '8'
    #首先在后面填充一个1
    if len(_m)%128 > 112:
        _m = _m + '0'*(128-len(_m)%128+112)+length
        # (l+1)%512>448先补余，然后再填448
    else:
        _m = _m + '0'*(112-len(_m)%128)+length
    group_m = SM3.Group(_m)
    group_number = len(group_m)
    V = [New_iv]
    #创建一个二维数组
    for i in range(group_number):
        V.append(SM3.CF(V,group_m,i))
    #逐步对分组进行迭代
    res = ''
    for va in V[group_number]:
        res += hex(va)[2:]
    return res


if __name__ == '__main__':
     #新的消息,在对原消息的填充后拼接要添加的消息
    new_m = pad_m + _m
    #得到hash3
    Hash3 = SM3.SM3(new_m)
    #得到hash2 计算m+padding+m'的hash值，如果攻击成功，hash2和hash3应该相等
    tic = timer()
    Hash2 = length_extend_attack(_m,pad_m_len)
    toc = timer()
    print(toc - tic,"s") # 输出的时间，秒为单位
    print("Hash2:",Hash2)
    print("Hash3:",Hash3)
    if Hash2 == Hash3:
        print("successful!")
