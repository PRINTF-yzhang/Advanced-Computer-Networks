# train model
# author Ying Zhang & Yujia Qiu
from sklearn.ensemble import RandomForestClassifier
from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import os

label_dict = {
    'Browser': 1,
    'Fruit': 2,
    'News': 3,
    'Weather': 4,
    'Youtube': 5
}

root_dir = 'feature/'
label_dir_list = os.listdir(root_dir)
print(label_dir_list)
feature_list = []
label_list = []
for label in label_dir_list:
    file_name_list = os.listdir(os.path.join(root_dir,label))
    # print(file_name_list)
    for file_name in file_name_list:
        file_path = os.path.join(root_dir,label,file_name)
        feature = pickle.load(open(file_path, "rb"))
        # print(feature)
        feature_list += feature
        label_list += [label_dict[label]] * len(feature)

model = RandomForestClassifier(n_estimators = 80)

print(len(feature_list))
print(len(label_list))
X_train, X_test, y_train, y_test = train_test_split(feature_list, label_list, test_size=0.5, random_state=6)

model.fit(X_train, y_train)
joblib.dump(model, 'model.pkl')
y_pred = model.predict(X_test)

target_names = ['Browser', 'Fruit', 'News', 'Weather', 'Youtube']
print(classification_report(y_test, y_pred, target_names=target_names))


"""
             precision    recall  f1-score   support

    Browser       0.83      0.75      0.79        20
      Fruit       0.70      0.84      0.76       169
       News       0.78      0.39      0.52        18
    Weather       0.74      0.70      0.72       155
    Youtube       0.82      0.63      0.71        67

avg / total       0.74      0.73      0.73       429


"""
