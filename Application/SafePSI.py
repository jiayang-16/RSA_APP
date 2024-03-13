import hashlib
import pandas as pd
import rsa
# import rsa.transform
# import rsa.core
from RSA import *


# public_user_dataset = pd.read_csv('users.csv')
class PublicKeyHolder:
    def __init__(self, pub, data: pd.DataFrame):
        self.pub = pub
        self.data = data
        self.n = self.pub[0]
        self.e = self.pub[1]
        assert "id" in self.data.columns
        self.data["hash"] = self.data["id"].apply(hash)

    def blind(self):
        assert "hash" in self.data.columns
        self.data[["blind_hash", "blind_inverse"]] = self.data["hash"].apply(
            # lambda x: pd.Series(self.pub.blind(x)))
            lambda x: pd.Series(blind_hide(self.n, self.e, x)))
        return self.data[["blind_hash"]]

    def unblind(self, data):
        assert "sign" in data.columns
        self.data["sign"] = data["sign"]
        self.data["encrypted_hash"] = self.data.apply(
            # lambda x: hash(self.pub.unblind(x["sign"], x["blind_inverse"])), axis=1)
            lambda x: hash(unblind_hide(self.n, x["sign"], x["blind_inverse"])), axis=1)

    def find_intersection(self, data):
        assert "encrypted_hash" in data.columns and "encrypted_hash" in self.data.columns
        return self.data[self.data["encrypted_hash"].isin(data["encrypted_hash"])]


class PrivateKeyHolder:
    def __init__(self, priv, data: pd.DataFrame):
        self.priv = priv
        self.data = data
        self.d = self.priv[2]
        self.n = self.priv[0]
        assert "id" in self.data.columns
        self.data["hash"] = self.data["id"].apply(hash)
        self.data["encrypted_hash"] = self.data["hash"].apply(
            lambda x: hash(pow_mod(x, self.d, self.n)))

    def sign(self, data):
        assert "blind_hash" in data.columns
        sign = pd.DataFrame()
        sign["sign"] = data["blind_hash"].apply(
            lambda x: pow_mod(x, self.d, self.n))
        return sign

    def get_encrypted_hash(self):
        return self.data[["encrypted_hash"]]

    def find_intersection(self, data):
        assert "encrypted_hash" in data.columns and "encrypted_hash" in self.data.columns
        return self.data[self.data["encrypted_hash"].isin(data["encrypted_hash"])]


def hash(msg):
    return rsa.transform.bytes2int(hashlib.sha256(str(msg).encode()).digest())


# private_user_A = pd.read_csv('users_A.csv')
# print(private_user_A.shape)
# private_user_B = pd.read_csv('users_B.csv')
# print(private_user_B.shape)
n = 512
# (pub, priv) = rsa.newkeys(n)
(pub, priv) = gen_keys(n)
print(pub, priv)
private_user_A = pd.read_csv('users_A.csv')
print(private_user_A.shape)

private_user_B = pd.read_csv('users_B.csv')
print(private_user_B.shape)

company_A = PublicKeyHolder(pub, private_user_A)
company_B = PrivateKeyHolder(priv, private_user_B)
blind_data = company_A.blind()
signed_data = company_B.sign(blind_data)
company_A.unblind(signed_data)
intersection_A = company_A.find_intersection(company_B.get_encrypted_hash())
print(intersection_A.shape)
intersection_B = company_B.find_intersection(intersection_A)
print(intersection_B.shape)
