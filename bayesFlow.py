# This file is for running an "online" approach
# to using TensorFlow
# When this file is run, it prints out the current statistics of predictions
# for the test sets

################
### PREAMBLE ###
################

from __future__ import division
from sklearn.feature_extraction.text import CountVectorizer
import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
import time
import tflow_bayes as parser

       
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

###################
### IMPORT DATA ###
###################

samples, malicious_samples = parser.parse("lotsodata.txt", "nb_probs.txt")

# counts for getting summary of results
truePos = 0
falsePos = 0
trueNeg = 0
falseNeg = 0

for j in range(len(samples) - 1):
    # We are using the j'th array for training, and the next one 
    # for testing
    if j != 0:
        trainData = malicious_samples[j-1] + samples[j]
        
    else:
        trainData = samples[j]
    
    testData = samples[j+1]

    # THIS WHOLE PROCESS COULD PROBABLY BE FACTORED OUT INTO
    # ANOTHER FUNCTION

    # First must get the data into format for TF to use
    # Start with training x matrix
    cleanTrain = []
    for element in trainData:
        #cleanTrain.append(element["ip"])
        cleanTrain.append(element["urlIP_Bayes"].replace('http://', ''))

    #vectorizer1 = CountVectorizer(analyzer='char', ngram_range=(4,4), max_features=2000)
    vectorizer1 = CountVectorizer(max_features=2000)
    X1 = vectorizer1.fit_transform(cleanTrain)
    trainX = np.array(X1.toarray())

    # Now make testing x matrix
    cleanTest = []
    for element in testData:
        #cleanTest.append(element["ip"])
        cleanTest.append(element["urlIP_Bayes"].replace('http://', ''))
        
    #vectorizer2 = CountVectorizer(analyzer='char', ngram_range=(4,4), max_features=2000, vocabulary=vectorizer1.vocabulary_)
    vectorizer2 = CountVectorizer(max_features=2000, vocabulary=vectorizer1.vocabulary_)
    X2 = vectorizer2.transform(cleanTest)
    testX = np.array(X2.toarray())

    # Make trainY matrix
    Y1 = []
    for i in range(len(trainData)):
        urlResult = []
        if trainData[i]['result'] == 'malicious':
            urlResult = [[1, 0]]
        else:
            urlResult = [[0, 1]]
        Y1 += urlResult
    trainY = np.array(Y1)

    # Make testY matrix
    Y2 = []
    for i in range(len(testData)):
        urlResult = []
        if testData[i]['result'] == 'malicious':
            urlResult = [[1, 0]]
        else:
            urlResult = [[0, 1]]
        Y2 += urlResult
    testY = np.array(Y2)

    print(trainX.shape)

    #########################
    ### GLOBAL PARAMETERS ###
    #########################

    ## DATA SET PARAMETERS
    # Get our dimensions for our different variables and placeholders:
    # numFeatures = the number of words extracted from each email
    numFeatures = trainX.shape[1]
    # numLabels = number of classes we are predicting (here just 2: Ham or Spam)
    numLabels = trainY.shape[1]

    ## TRAINING SESSION PARAMETERS
    # number of times we iterate through training data
    # tensorboard shows that accuracy plateaus at ~25k epochs
    numEpochs = 7000

    # a smarter learning rate for gradientOptimizer
    learningRate = tf.train.exponential_decay(learning_rate=0.0008,
                                              global_step= 1,
                                              decay_steps=trainX.shape[0],
                                              decay_rate= 0.95,
                                              staircase=True)

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

    # Values are randomly sampled from a Gaussian with a standard deviation of:
    #     sqrt(6 / (numInputNodes + numOutputNodes + 1))

    weights = tf.Variable(tf.random_normal([numFeatures,numLabels],
                                           mean=0,
                                           stddev=(np.sqrt(6/numFeatures+
                                                             numLabels+1)),
                                           name="weights"))

    bias = tf.Variable(tf.random_normal([1,numLabels],
                                        mean=0,
                                        stddev=(np.sqrt(6/numFeatures+numLabels+1)),
                                        name="bias"))


    # INITIALIZE our weights and biases
    init_OP = tf.initialize_all_variables()

    ######################
    ### PREDICTION OPS ###
    ######################

    # PREDICTION ALGORITHM i.e. FEEDFORWARD ALGORITHM
    apply_weights_OP = tf.matmul(X, weights, name="apply_weights")
    add_bias_OP = tf.add(apply_weights_OP, bias, name="add_bias") 
    activation_OP = tf.nn.sigmoid(add_bias_OP, name="activation")

    #####################
    ### EVALUATION OP ###
    #####################

    # COST FUNCTION i.e. MEAN SQUARED ERROR
    cost_OP = tf.nn.l2_loss(activation_OP-yGold, name="squared_error_cost")

    #######################
    ### OPTIMIZATION OP ###
    #######################

    # OPTIMIZATION ALGORITHM i.e. GRADIENT DESCENT
    training_OP = tf.train.GradientDescentOptimizer(learningRate).minimize(cost_OP)

    #####################
    ### RUN THE GRAPH ###
    #####################

    # Create a tensorflow session
    sess = tf.Session()

    # Initialize all tensorflow variables
    sess.run(init_OP)

    # Initialize reporting variables
    cost = 0
    diff = 1

    # Training epochs
    for i in range(numEpochs):
        if i > 1 and diff < .0001:
            print("change in cost %g; convergence."%diff)
            break
        else:
            # Run training step
            step = sess.run(training_OP, feed_dict={X: trainX, yGold: trainY})


    ##############################
    ### SAVE TRAINED VARIABLES ###
    ##############################

    # Create Saver
    saver = tf.train.Saver()
    # Save variables to .ckpt file
    saver.save(sess, "trained_variables.ckpt")


    ############################
    ### MAKE NEW PREDICTIONS ###
    ############################

    # Close tensorflow session
    sess.close()
    tf.reset_default_graph()

    #########################
    ### GLOBAL PARAMETERS ###
    #########################

    # Get our dimensions for our different variables and placeholders:
    # numFeatures = the number of words extracted from each email
    # numFeatures = trainX.shape[1]
    # numLabels = number of classes we are predicting (here just 2: ham or spam)
    # numLabels = trainY.shape[1]

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

    #show predictions and accuracy of entire test set
    prediction, evaluation = sess.run([activation_OP, accuracy_OP], feed_dict={X: testX, yGold: testY})

    # Print out the results
    for i in range(len(testX)):
        predictionLabel = labelToString(prediction[i])
        actualLabel = labelToString(testY[i])
        if(predictionLabel == "malicious"):
            if(actualLabel == "malicious"):
                truePos += 1
            else:
                falsePos += 1
        else:
            if(actualLabel == "malicious"):
                falseNeg += 1
            else:
                trueNeg += 1

        #print("regression predicts email %s to be %s and is actually %s" %(str(i + 1), labelToString(prediction[i]), labelToString(testY[i])))
    print("Predicted Malicious & Actually Malicious: %s" %str(truePos))
    print("Predicted Clean & Actually Malicious: %s" %str(falseNeg))
    print("Predicted Clean & Actually Clean: %s" %str(trueNeg))
    print("Predicted Malicious & Actually Clean: %s" %str(falsePos))
    print("overall accuracy of dataset: %s percent" %str(evaluation))

    tf.reset_default_graph()
