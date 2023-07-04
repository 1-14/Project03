# Project3

## 长度扩展攻击原理

在密码学中长度延展攻击就是指攻击者通过已知的hash(message1)和message1的长度，从而能够知道hash（message1‖message2）的值。其中‖ 表示的是连接符。并且攻击者并不需要知道message1到底是什么。由于
SM3基于MD结构，而MD结构具有分块迭代处理的特性，故可以对SM3进行长度扩展攻击。

MD结构流程图大致如下

![image](https://user-images.githubusercontent.com/104854836/181997181-e0ec000e-8cfd-4275-9564-2c3487ada9e7.jpg)  

## cpu型号 

11th Gen Intel(R)Core(TM)i7-11800H@2.30GHz

## SM3长度扩展攻击代码原理

根据长度扩展攻击的原理

第一步，我们首先需要计算消息m的哈希值H(m)和H(m)的长度

第二步，H(m)拼接一个新消息_m进行长度扩展攻击

第三步，将攻击结果与（pad(m)||_m）的哈希值进行对比，若相同，则长度扩展攻击成功，伪造了新消息（pad(m)||_m）。

## SHA256长度扩展攻击代码原理

基本同上

## 关键代码展示

### sm3

```
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
```

### sha256

```
def length_extansion_attack(Original_message, Original_hash, keylen, Forge_message):
    state = reverse_internal_state(Original_hash)
    Original_message_padded = sha256_padding(Original_message, keylen)
    Forge_hash = Sha256(Forge_message, state, init_length=len(Original_message_padded) + keylen).hex()
    _Forge_message = Original_message_padded + bytearray(Forge_message, 'ascii')

    return _Forge_message, Forge_hash

```
在length_extansion_attack函数中，我们接收原始消息、原始哈希值、密钥长度和欲伪造的消息作为输入。首先，我们使用reverse_internal_state函数将原始哈希值转换为内部状态数组。然后，我们对原始消息进行填充，并使用填充后的消息长度和初始内部状态进行SHA-256计算，得到伪造的哈希值。最后，我们将填充后的原始消息与欲伪造的消息连接起来，形成最终伪造的消息。

## 结果展示

### sm3

![image](https://github.com/1-14/Project3/blob/main/3.png)  

忽略前面报错代码，是由导入模块造成的，不影响程序正常运行，对比两个哈希值，可以发现完全相同，长度扩展攻击成功，并且时间仅0.0005s，速度非常快。

### sha256

![image](https://github.com/1-14/Project3/blob/main/2.png)


## 结果分析

### sm3

在实验中，首先随机生成一个消息m，然后计算其哈希值Hash1。接下来，生成m的填充，并记录填充后的长度pad_m_len。然后，构造一个新的消息_m（即附加消息），将其加入填充后的消息pad_m中，形成新的消息new_m。
通过调用length_extend_attack函数，使用_m和pad_m_len进行长度扩展攻击。在该函数中，首先将Hash1的后8个向量作为初始变量New_iv。然后计算加上_m后的消息总长度length。接下来，根据填充规则，将填充位和长度添加到_m中，得到填充后的消息。将填充后的消息进行分组，并进行迭代计算，得到伪造的哈希值Hash2。

同时，通过调用SM3.SM3函数，计算新消息new_m的哈希值Hash3。最后，比较Hash2和Hash3是否相等，如果相等，则攻击成功。

根据实验结果，Hash2和Hash3相等，输出"successful!"表示攻击成功。

### sha256

在if __name__ == '__main__':部分，我们设置了一个示例场景，用于演示长度扩展攻击的效果。我们选择了一个密钥和原始消息，并计算了其SHA-256哈希值。然后，我们选择一个要附加的消息，调用length_extansion_attack函数进行长度扩展攻击。最后，我们使用原始密钥、填充后的原始消息和附加消息进行SHA-256计算，并比较生成的哈希值与伪造的哈希值，以验证攻击是否成功。

实验结果将输出原始消息、附加消息、构造的哈希值以及新消息的哈希值

根据实验结果，hash_attack和hash_extend相等，输出攻击成功

























