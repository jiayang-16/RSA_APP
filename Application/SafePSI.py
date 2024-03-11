import hashlib
import pandas as pd
import rsa
import rsa.transform
import rsa.core


# public_user_dataset = pd.read_csv('users.csv')


def hash(msg):
    if isinstance(msg, int):
        msg = str(msg)
    return rsa.transform.bytes2int(hashlib.sha256(msg.encode()).digest())


# private_user_A = pd.read_csv('users_A.csv')
# print(private_user_A.shape)
# private_user_B = pd.read_csv('users_B.csv')
# print(private_user_B.shape)
n = 512
(pub, priv) = rsa.newkeys(n)

# assume only B has the private key
private_user_A = pd.read_csv('users_A.csv')
print(private_user_A.shape)
private_user_A["hash"] = private_user_A["id"].apply(hash)
private_user_A[["blind_hash", "blind_inverse"]] = private_user_A["hash"].apply(
    lambda x: pd.Series(priv.blind(x)))

private_user_B = pd.read_csv('users_B.csv')
print(private_user_B.shape)
private_user_B["hash"] = private_user_B["id"].apply(hash)
private_user_B["encrypted_hash"] = private_user_B["hash"].apply(
    lambda x: hash(rsa.core.encrypt_int(x, priv.d, priv.n)))

msg_send_to_B = private_user_A[["blind_hash"]].copy()
msg_send_to_B["sign"] = msg_send_to_B["blind_hash"].apply(
    lambda x: rsa.core.encrypt_int(x, priv.d, priv.n))

msg_send_to_A = private_user_B[["encrypted_hash"]].copy()
msg_return_to_A = msg_send_to_B.copy()
private_user_A["sign"] = msg_send_to_B["sign"]

private_user_A["encrypted_hash"] = private_user_A.apply(
    lambda x: hash(priv.unblind(x["sign"], x["blind_inverse"])), axis=1)

# A find intersection
intersection_A = pd.merge(private_user_A, msg_send_to_A, on="encrypted_hash", how="inner")
print(intersection_A.shape)

# B find intersection
msg_return_to_B = intersection_A[["encrypted_hash"]].copy()
intersection_B = private_user_B[private_user_B["encrypted_hash"].isin(msg_return_to_B["encrypted_hash"])]
print(intersection_B.shape)