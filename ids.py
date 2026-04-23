#Importing the dependencies
import numpy as np
import pandas as pd
#import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix,classification_report
import matplotlib.pyplot as plt
from sklearn.naive_bayes import GaussianNB
from sklearn import preprocessing
from sklearn import svm
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import  DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
#from xgboost import XGBClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LinearRegression
from sklearn.neural_network import MLPClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
import streamlit as st
import base64
import pickle as pk




#configuring the page setup
st.set_page_config(page_title='Intrusion detection system',layout='centered')

with st.sidebar:
    st.header("Main Menu")
    selection=st.radio("select your options",options=["Single ID Detection", "Multiple ID Detection"]
)


# File download
def filedownload(df):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()  # strings <-> bytes conversions
    href = f'<a href="data:file/csv;base64,{b64}" download="prediction.csv">Download your prediction</a>'
    return href


def IntrusionDetector(givendata):
    loaded_model = pk.load(open("neuron_shield.pkl", "rb"))
    
    input_data_as_numpy_array = np.asarray(givendata)
    input_data_reshaped = input_data_as_numpy_array.reshape(1, -1)

    std_scaler_loaded = pk.load(open("neuron_scaler.pkl", "rb"))
    std_X_resample = std_scaler_loaded.transform(input_data_reshaped)

    prediction = loaded_model.predict(std_X_resample)

    if prediction[0] == 1 or prediction[0] == "1":
        return "Attack Detected"
    else:
        return "No Sign of Attack Detected"


def main():
    col1, col2 = st.columns([1, 3])

    with col1:
        st.header("Neuro Shield")
    
    with col2:
        st.image("logo.png", width=120)


    network_packet_size = st.number_input("Network Packet Size", min_value=0.0, step=1.0)
    
    protocol_type = st.selectbox("Protocol Type", ("", "TCP", "UDP", "ICMP"))
    if protocol_type == "TCP":
        protocol_type_value = 0
    elif protocol_type == "UDP":
        protocol_type_value = 1
    elif protocol_type == "ICMP":
        protocol_type_value = 2
    else:
        protocol_type_value = None

    login_attempts = st.number_input("Login Attempts", min_value=0, step=1)
    
    session_duration = st.number_input("Session Duration", min_value=0.0, step=1.0)

    encryption_used = st.selectbox("Encryption Used", ("", "Yes", "No"))
    if encryption_used == "Yes":
        encryption_used_value = 1
    elif encryption_used == "No":
        encryption_used_value = 0
    else:
        encryption_used_value = None

    ip_reputation_score = st.number_input("IP Reputation Score", min_value=0.0, step=1.0)

    failed_logins = st.number_input("Failed Logins", min_value=0, step=1)

    browser_type = st.selectbox("Browser Type", ("", "Chrome", "Firefox", "Safari", "Edge", "Opera", "Other"))
    if browser_type == "Chrome":
        browser_type_value = 0
    elif browser_type == "Firefox":
        browser_type_value = 1
    elif browser_type == "Safari":
        browser_type_value = 2
    elif browser_type == "Edge":
        browser_type_value = 3
    elif browser_type == "Opera":
        browser_type_value = 4
    elif browser_type == "Other":
        browser_type_value = 5
    else:
        browser_type_value = None

    unusual_time_access = st.selectbox("Unusual Time Access", ("", "Yes", "No"))
    if unusual_time_access == "Yes":
        unusual_time_access_value = 1
    elif unusual_time_access == "No":
        unusual_time_access_value = 0
    else:
        unusual_time_access_value = None

    detectionResult = ""

    if st.button("Predict"):
        if (
            protocol_type_value is None
            or encryption_used_value is None
            or browser_type_value is None
            or unusual_time_access_value is None
        ):
            st.warning("Please fill in all fields before prediction.")
        else:
            detectionResult = IntrusionDetector([
                network_packet_size,
                protocol_type_value,
                login_attempts,
                session_duration,
                encryption_used_value,
                ip_reputation_score,
                failed_logins,
                browser_type_value,
                unusual_time_access_value
            ])
            st.success(detectionResult)




def multi(input_data):
    loaded_model = pk.load(open("neuron_shield.pkl", "rb"))
    std_scaler_loaded = pk.load(open("neuron_scaler.pkl", "rb"))

    dfinput = pd.read_csv(input_data)

    st.header("Preview of the Dataset")
    st.dataframe(dfinput)

    features = dfinput[['network_packet_size', 'protocol_type', 'login_attempts',
                        'session_duration', 'encryption_used', 'ip_reputation_score',
                        'failed_logins', 'browser_type', 'unusual_time_access']]

    std_dfinput = std_scaler_loaded.transform(features.values)

    predict = st.button("Click to Predict")

    if predict:
        prediction = loaded_model.predict(std_dfinput)

        results = []
        for i in prediction:
            if i == 1:
                results.append("Attack Detected")
            else:
                results.append("No Sign of Attack Detected")

        dfresult = dfinput.copy()
        dfresult["Intrusion Detection Result"] = results

        st.subheader("Prediction Output")
        st.dataframe(dfresult)
        st.markdown(filedownload(dfresult), unsafe_allow_html=True)
        


if selection == "Single ID Detection":
    main()

if selection == "Multiple ID Detection":
    st.header("Make Multiple Prediction of Your Logs")
    uploaded_file = st.file_uploader("", type=["csv"])

    if uploaded_file is not None:
        multi(uploaded_file)
    else:
        st.info("No Dataset has been uploaded yet!")
