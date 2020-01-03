CS 4516: Advanced Computer Networks, Phase 3
============================================

Yujia Qiu
Ying Zhang


Python Packages
---------------

Python 3 was used for this phase. Required packages include:

* scipy
* statistics
* scikit-learn
* pyshark
* pickle

Classification Vectors
----------------------

We train a random forest classifier on the feature vectors as follows:

* Protocol (1 for TCP, 0 for UDP)
* Byte ratio (bytes sent / bytes received, or reciprocal)
* Packet ratio (packets sent / packets received, or reciprocal)
* Mean packet length
* Min packet length
* Max packet length
* Standard deviation of packet lengths (zero if n <= 2)
* Packet length kurtosis
* Packet length skew
* Mean time gap between each packet (zero if n <= 1)
* Min time gap
* Max time gap
* Standard deviation of packet lengths (zero if n <= 2)
* Time gap kurtosis
* Time gap skew

Results
-------
We split data using the following code:
X_train, X_test, y_train, y_test = train_test_split(feature_list, label_list, test_size=0.5, random_state=6)

The accuracies of the test dataset are shown as follows:

             precision    recall  f1-score   support

    Browser       0.83      0.75      0.79        20
      Fruit       0.70      0.84      0.76       169
       News       0.78      0.39      0.52        18
    Weather       0.74      0.70      0.72       155
    Youtube       0.82      0.63      0.71        67
    
avg / total       0.74      0.73      0.73       429
