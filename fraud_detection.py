from joblib import load
import tensorflow as tf

# Function to load model
def load_model(path):
    model = tf.keras.models.load_model(path)
    return model

# Function to load preprocessor
def load_preprocessor(path):
    p = load(path)
    return p

# Function to predict
def predict(model_path, prepro_path, data_dict):
    model = load_model(model_path)
    p = load_preprocessor(prepro_path)
    X = p.transform(data_dict)  # transforming data dictionary to array
    y_pred = model.predict(X)   # predicting result
    return y_pred


if __name__ == '__main__':
    import pandas as pd
    data = pd.DataFrame({
        'step': [1],
        'type': ['CASH_OUT'],
        'amount': [1000],
        'name_orig': ['C12345'],
        'oldbalanceOrg': [1000],
        'newbalanceOrig': [0],
        'name_dest': ['M12345'],
        'oldbalanceDest': [0],
        'newbalanceDest': [0],
    })  # data frame containing data to predict
    model_path = r'models\v1\ann_fraud_detection.h5'    # path to model
    pp_path = r'models\v1\ann_fraud_detection_preprocessor.jb'  # path to preprocessor
    out = predict(model_path, pp_path, data)    # prediction
    print(out[0][0] > 0.5)  # Checking the prediction
    if out[0][0] > 0.5:
        print('Fraud')
    else:
        print('Not Fraud')