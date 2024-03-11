import hashlib
import pandas as pd

public_user_dataset = pd.read_csv('users.csv')


def hash(user_id):
    if isinstance(user_id, int):
        user_id = str(user_id)
    return hashlib.sha256(user_id.encode()).hexdigest()


private_user_A = pd.read_csv('users_A.csv')
print(private_user_A.shape)
private_user_A["hash"] = private_user_A["id"].apply(hash)

private_user_B = pd.read_csv('users_B.csv')
print(private_user_B.shape)
private_user_B["hash"] = private_user_B["id"].apply(hash)
# intersection
intersection = pd.merge(private_user_B, private_user_A, on="hash", how="inner")
print(intersection.shape)


def hack(hash_list):
    public_user_dataset_for_hack = public_user_dataset.copy()
    public_user_dataset_for_hack["hash"] = public_user_dataset_for_hack["id"].apply(hash)
    return public_user_dataset_for_hack[public_user_dataset_for_hack["hash"].isin(hash_list)]


hacked_user_info = hack(private_user_A["hash"].tolist())
print(hacked_user_info.shape)
