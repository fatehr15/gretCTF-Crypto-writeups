# Tung Tung Tung Sahur
By:zor_4n6


---

## Challenge Description
**Challenge Name:** Tung Tung Tung Sahur

**Category:** Cryptography (EZPZ)

**Author**: elijah5399

**Difficulty:** Easy 

**Description:**  

New to the world of brainrot? Not sure what names to pick from? We've got you covered with a list of our faves:

* Tralalero Tralala
* Chef Crabracadabra
* Boneca Ambalabu
* Tung Tung Tung Tung Tung Tung Tung Tung Tung Sahur

You're given Python code that performs some custom encryption based on RSA. The output looks like this:

```python
e = 3
N = 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841
C = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351
```

Also, the program prints:

```
Tung!
Tung!
...
Sahur!
```

---

##  Challenge Analysis

The code follows these steps:

1. A random 1024-bit RSA modulus `N` is generated.
2. A flag is converted to an integer `m = bytes_to_long(flag)`.
3. A small public exponent `e = 3` is used.
4. The ciphertext is calculated as `C = pow(m, e)`.
5. While `C < N`, it is doubled (printing `"Tung!"`).
6. Once `C >= N`, it subtracts `N` repeatedly until `C < N` (printing `"Sahur!"`).

This produces a final ciphertext:

```python
C = m^3 * 2^k − N * l
```

From the output:

* There are `k = 20` "Tung!" prints.
* One "Sahur!" print → `l = 1`

So we can derive:

```
m^3 * 2^k = C + N
=> m^3 = (C + N) // 2^k
```

---

## 🛠️ Exploitation & Solution

Given `C`, `N`, and `k = 20`, we can directly compute the plaintext:

```python
from Crypto.Util.number import *

e = 3
k = 20

N = 140435453730354645791411355194663476189925572822633969369789174462118371271596760636019139860253031574578527741964265651042308868891445943157297334529542262978581980510561588647737777257782808189452048059686839526183098369088517967034275028064545393619471943508597642789736561111876518966375338087811587061841

C = 49352042282005059128581014505726171900605591297613623345867441621895112187636996726631442703018174634451487011943207283077132380966236199654225908444639768747819586037837300977718224328851698492514071424157020166404634418443047079321427635477610768472595631700807761956649004094995037741924081602353532946351

# Undo the transformation
m_cubed = (C + N) // (2 ** k)
m = iroot(m_cubed, 3)[0]

flag = long_to_bytes(m)
print(flag)
```

### 🏁 Flag

```
grey{tUn9_t00nG_t0ONg_x7_th3n_s4hUr}
```

---

## Key Takeaways

* This is a twist on **low-exponent RSA** where the ciphertext is modified with doubling and modulus reduction.
* Knowing the number of operations allows us to reverse them easily.
* `e = 3` with no padding makes **cube root attacks** possible if `m^3 < N`.

---

## Brainrot References

* The repeated "Tung!" and "Sahur!" are meme elements from Indonesian or Malay brainrot meme culture, referencing sounds associated with chaotic Ramadan mornings.
* Challenge adds a fun and humorous twist while staying technically sound. The first one I solved (My scrolling time isn't for nothing XD)

---

**Flag**: `grey{tUn9_t00nG_t0ONg_x7_th3n_s4hUr}`
