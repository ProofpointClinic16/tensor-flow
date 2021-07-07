from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import tensorflow as tf
import parser
from make_balanced_sets import create_sets


###################
### IMPORT DATA ###
###################

#Comment block below is original code used but is now replaced with the code immediately
# following it, up to Global Variables section.
'''
# Insert a filename here
data = parser.parse('lotsodata.txt')

clean = []
for element in data:
    clean.append(element["url"].replace('http://', ''))

vectorizer = CountVectorizer(max_features=1000)

X = vectorizer.fit_transform(clean)
arrayX = np.array(X.toarray())
trainTestXArray = np.array_split(arrayX, 2)

trainX = trainTestXArray[0]
testX = trainTestXArray[1]

Y = []
# Make trainY matrix
for i in range(len(data)):
    urlResult = []
    if data[i]['result'] == 'malicious':
        urlResult = [[1, 0]]
    else:
        urlResult = [[0, 1]]
    Y += urlResult

arrayY = np.array(Y)
trainTestYArray = np.array_split(arrayY, 2)

trainY = trainTestYArray[0]
testY = trainTestYArray[1]
'''

#Code below is taken from modified tensorflow_train.py
data = create_sets('august_scans_nosample_145970.txt', 5500)

training_set = data[0]
testing_set = data[1]

cleanTrain = []
cleanTest = []

for element1 in training_set:
    cleanTrain.append(element1["url"].replace('http://', ''))


for element2 in testing_set:
    cleanTest.append(element2["url"].replace('http://', ''))

vectorizer = CountVectorizer(max_features=1000)

X1 = vectorizer.fit_transform(cleanTrain)
X2 = vectorizer.fit_transform(cleanTest)

trainX = np.array(X1.toarray())
testX = np.array(X2.toarray())


Y1 = []
Y2 = []

for i in range(len(training_set)):
    urlResult1 = []
    if training_set[i]['result'] == 'malicious':
        urlResult1 = [[1, 0]]
    else:
        urlResult1 = [[0, 1]]
    Y1 += urlResult1

for i in range(len(testing_set)):
    urlResult2 = []
    if testing_set[i]['result'] == 'malicious':
        urlResult2 = [[1, 0]]
    else:
        urlResult2 = [[0, 1]]
    Y2 += urlResult2

trainY = np.array(Y1)
testY = np.array(Y2)

#########################
### GLOBAL PARAMETERS ###
#########################

# Get our dimensions for our different variables and placeholders:
# numFeatures = the number of words extracted from each email
numFeatures = trainX.shape[1]
# numLabels = number of classes we are predicting (here just 2: ham or spam)
numLabels = trainY.shape[1]

#create a tensorflow session
sess = tf.Session()


####################
### PLACEHOLDERS ###
####################

# X = X-matrix / feature-matrix / data-matrix... It's a tensor to hold our email
# data. 'None' here means that we can hold any number of emails
X = tf.placeholder(tf.float32, [None, numFeatures])
# yGold = Y-matrix / label-matrix / labels... This will be our correct answers
# matrix. Every row has either [1,0] for SPAM or [0,1] for HAM. 'None' here
# means that we can hold any number of emails
yGold = tf.placeholder(tf.float32, [None, numLabels])


#################
### VARIABLES ###
#################

#all values must be initialized to a value before loading can occur

weights = tf.Variable(tf.zeros([numFeatures,numLabels]))

bias = tf.Variable(tf.zeros([1,numLabels]))

########################
### OPS / OPERATIONS ###
########################

#since we don't have to train the model, the only Ops are the prediction operations

apply_weights_OP = tf.matmul(X, weights, name="apply_weights")
add_bias_OP = tf.add(apply_weights_OP, bias, name="add_bias")
activation_OP = tf.nn.sigmoid(add_bias_OP, name="activation")


# argmax(activation_OP, 1) gives the label our model thought was most likely
# argmax(yGold, 1) is the correct label
correct_predictions_OP = tf.equal(tf.argmax(activation_OP,1),tf.argmax(yGold,1))

# False is 0 and True is 1, what was our average?
accuracy_OP = tf.reduce_mean(tf.cast(correct_predictions_OP, "float"))

# Initializes everything we've defined made above, but doesn't run anything
# until sess.run()
init_OP = tf.initialize_all_variables()

sess.run(init_OP)       #initialize variables BEFORE loading

#load variables from file
saver = tf.train.Saver()
saver.restore(sess, "trained_variables.ckpt")

#####################
### RUN THE GRAPH ###
#####################

# Initialize all tensorflow objects
# sess.run(init_OP)

#method for converting tensor label to string label
def labelToString(label):
    if np.argmax(label) == 0:
        return "malicious"
    else:
        return "clean"

#make prediction on a given test set item
def predict(features, goldLabel):
    #run through graph
    tensor_prediction = sess.run(activation_OP, feed_dict={X: features.reshape(1, len(features)), yGold: goldLabel.reshape(1, len(goldLabel))})      #had to make sure that each input in feed_dict was an array
    prediction = labelToString(tensor_prediction)
    actual = labelToString(goldLabel)
    print("regression predicts email to be %s and is actually %s" %(prediction, actual))

if __name__ == "__main__":

    #show predictions and accuracy of entire test set
    prediction, evaluation = sess.run([activation_OP, accuracy_OP], feed_dict={X: testX, yGold: testY})

    for i in range(len(testX)):
        print("regression predicts email %s to be %s and is actually %s" %(str(i + 1), labelToString(prediction[i]), labelToString(testY[i])))
    print("overall accuracy of dataset: %s percent" %str(evaluation))

