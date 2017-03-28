import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn import svm,cross_validation,tree,linear_model,preprocessing,metrics
from sklearn.mixture import GMM
from sklearn.grid_search import GridSearchCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression,SGDClassifier
from sklearn.naive_bayes import GaussianNB,BernoulliNB

class Processor:

	@staticmethod
	def cleanData(file_name, ):
		data = pd.read_csv(file_name, sep=",", header = None)
		attack_type = pd.read_csv('Attack Types.csv', names=["class", "type"])
		data.columns = ["duration", "protocol_type", "service", "flag" ,"src_bytes"
		    , "dst_bytes", "land", "wrong_fragment", "urgent"
		    , "hot", "num_failed_logins", "logged_in", "num_compromised"
		    , "root_shell", "su_attempted", "num_root", "num_file_creations"
		    , "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login"
		    , "is_guest_login", "count", "srv_count", "serror_rate"
		    , "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate"
		    , "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count"
		    , "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate"
		    , "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
		    , "class", "unknown"]
		attack_type_mapping = dict(zip(attack_type['class'], attack_type['type']))
		data['attackType'] = data['class'].map(attack_type_mapping)
		data = data.drop(['unknown'], axis = 1)
		data = data.drop(['class'], axis = 1)

		attackType_list = data['attackType'].unique().tolist()
		attack_type_mapping = dict(zip(attackType_list, range(0, len(attackType_list))))
		data['attack_type'] = data['attackType'].map(attack_type_mapping).astype(int)
		data = data.drop(['attackType'], axis = 1)
		return data, attackType_list

	@staticmethod
	def process(data, start, end):
		y = data['isNormal'][start:end]
		dataX = pd.get_dummies(data.drop(['isNormal'], axis = 1))[start:end]
		X = dataX.values
		return X, y

	@staticmethod
	def normalize(data):
		mu = data.select_dtypes(['float64', 'int64']).mean(axis=0)
		sigma = data.select_dtypes(['float64', 'int64']).std(axis=0)
		for column in data.select_dtypes(['float64', 'int64']).columns:
			if sigma[column] != 0:
				data[column] = ( data[column] - mu[column] ) / sigma[column]
		return data

class EnsembleClassifier(object):
	def __init__(self, clfs=None):
		self.clfs = clfs;

	def fit(self, train_X, train_y):
		for clf in self.clfs:
			clf.fit(train_X, train_y)

	def predict(self, test_X):
		self.predictions_ = []
		for clf in self.clfs:
			try:
				self.predictions_.append(clf.best_estimator_.predict(testX))
			except:
				self.predictions_.append(clf.predict(test_X))
		# vote the results
		predMat = np.array(self.predictions_)
		result = np.zeros(predMat.shape[1])
		for i in xrange(predMat.shape[1]):
			temp = np.bincount(predMat[:,i])
			# if all disagree with each other, vote for the first classifier
			if np.max(temp) == 1:
				result[i] = predMat[0,i]
			else:
				result[i] = np.argmax(temp)
		return result