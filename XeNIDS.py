import pandas as pd
import numpy as np

import argparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
import _pickle as cPickle
import os
from os import listdir
from os.path import isfile, join

#define the parser
parser = argparse.ArgumentParser(description='XeNID evaluator framework')
parser.add_argument('--task', default = 'baseline')
parser.add_argument('--dataset', default = 'hom')

def get_dataset_name(type_of_execution):
    if type_of_execution == 'hom':
        result = ["NF-BoT-IoT", "NF-CSE-CIC-IDS2018", "NF-ToN-IoT" ,"NF-UNSW-NB15"]
    elif type_of_execution == 'nonhom':
         result = ["CTU13", "DDOS19", "IDS17" ,"NB15"]
    return result

def get_target_features_name(type_of_execution):
    if type_of_execution == 'hom':
            X_features = ['XeNID__src_ip_type','XeNID__trg_ip_type',
            'XeNID__src_port_type','XeNID__trg_port_type',
                'XeNID__flow_duration','XeNID__flow_direction',
                'XeNID__rcv_bytes', 'XeNID__fwd_bytes', 'XeNID__tot_bytes',
                'XeNID__rcv_pckt', 'XeNID__fwd_pckt', 'XeNID__tot_pckt']
            Y_features = 'XeNID__Label'

    elif type_of_execution == 'nonhom':
         X_features = ['src_ip_type', 'dst_ip_type',
            'src_port_type', 'dst_port_type', 'flow_duration', 'flow_direction',
            'fwd_bytes', 'rcv_bytes', 'tot_bytes', 'fwd_pack', 'rcv_pack',
            'tot_pack']

         #Y_features = 'XeNID__Label'
         Y_features = 'label'

    return X_features, Y_features

def get_csvs(type_of_execution, network, benign = True, test = True):
    #define the path with the csvs
    path = f"./Dataset/{type_of_execution}/{network}/data/"

    #get the list of csv files
    CsvFiles = [path + f for f in listdir(path) \
        if isfile(join(path, f)) and  f.endswith(".csv")]

    # print(CsvFiles)

    #maintain only the required partition
    partition = 'train'
    if test:
        partition = 'test'
    CsvFiles = [x for x in CsvFiles if partition+'_' in x]

    # print(CsvFiles)

    #check if benign or attacks
    if benign:
        CsvFiles = [x for x in CsvFiles if "benign" in x.lower()][0]
    else:
        CsvFiles = [x for x in CsvFiles if "benign" not in x.lower()]

    return CsvFiles

def get_attack_name_from_model(name):
    #delete the path
    name = name.split('/')[-1]

    #split the name
    name = name.split('_')

    #remove the prefix:
    # [0]: model type
    # [1]: src network
    # [2]: trg network
    name = name[3:]

    #remove suffix
    name = name[:-1]

    #get the result
    name = '_'.join(name)
    return name

def get_attack_name_from_csv(name):
    #delete the path
    name = name.split('/')[-1]

    #remove extension
    name = name[:-4]

    #remove the prefix
    name = name.split("_")[1:]
    name = '_'.join(name)



    # raise Exception(f"DEB:\t\t{name}")
    return name

def run_baseline(networks, X_features, Y_features, type_of_execution):
    """ in the baseline performance, both benign and malicious samples are collected
    on the same networking evironment """
    #define the dataset with the results
    res_df = pd.DataFrame(None, columns = ["SrcNetwork", "TrgNetwork", "Attack", "Metric", "Score"])

    #start evaluation
    for benign_net in networks: #iterate over the benign networks
        print(f"\n\nStart evaluating {benign_net}")

        #iterate over the malicious networks
        for malicious_net in networks:
            #we work only on the "diagonal" --> same networks
            if benign_net == malicious_net:
                #identify the model's path
                path = f"./Models/{type_of_execution}/{benign_net}_B/{malicious_net}_M/"

                #get the list of the pkl files to load
                models_path= [path + f for f in listdir(path) \
                if isfile(join(path, f)) and f.endswith(".pkl")]

                #get csvs paths
                benign_path = get_csvs(type_of_execution = DATASET,
                    network = benign_net,
                    benign = True,
                    test = True)

                malicious_paths = get_csvs(type_of_execution = DATASET,
                    network = malicious_net,
                    benign = False,
                    test = True)


                #iterate over the attacks
                for curr_attack in models_path:
                    #extract the attack name from the model path
                    # curr_attack_name = curr_attack.split('/')[-1] #remove the path
                    # curr_attack_name = curr_attack_name[:-5] #remove the suffix
                    # curr_attack_name = curr_attack_name.split("_")[-1] #remove the suffix
                    curr_attack_name = get_attack_name_from_model(curr_attack)
                    #select the malicious csv
                    try:
                        curr_malicious_path = [x for x in malicious_paths if curr_attack_name == get_attack_name_from_csv(x)][0]
                    except:
                        curr_malicious_path = [x for x in malicious_paths if curr_attack_name == x.split('/')[-1][:-4].split("_")[1]]
                        raise Exception(f"Attack:{curr_attack_name}\n{malicious_paths}\n{curr_malicious_path}")
                    # print(curr_attack, curr_attack_name, curr_malicious_path)

                    #load the classifier
                    with open(curr_attack, 'rb') as fid:
                        clf = cPickle.load(fid)

                    #define the csv
                    te_paths = [benign_path, curr_malicious_path]
                    df_test = pd.concat([pd.read_csv(f, low_memory = False) for f in te_paths])

                    #define X and Y
                    X_test = df_test[X_features]
                    Y_test = df_test[Y_features].tolist()

                    #evaluate the test
                    y_test_pred = clf.predict(X_test)

                    #evaluation
                    test_f1 = f1_score(Y_test, y_test_pred, average = 'macro')
                    test_prec = precision_score(Y_test, y_test_pred)
                    test_recall = recall_score(Y_test, y_test_pred)
                    tn, fp, fn, tp = confusion_matrix(Y_test, y_test_pred).ravel()

                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "F1", test_f1]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "Precision", test_prec]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "Recall", test_recall]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "TN", tn]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "TP", tp]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "FN", fn]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack, "FP", fp]

        print(f"\t--->cycle terminated.\n\n")

    return res_df

def run_extendibility(networks, X_features, Y_features, type_of_execution):
    """ in the extendibility performance, both benign and malicious samples are collected
    on the same networking evironment """
    #define the dataset with the results
    res_df = pd.DataFrame(None, columns = ["SrcNetwork", "TrgNetwork", "Attack", "Metric", "Score"])

    #start evaluation
    for benign_net in networks: #iterate over the benign networks
        print(f"\n\nStart evaluating {benign_net}")

        #iterate over the malicious networks
        for malicious_net in networks:
            #we avoid the "diagonal" --> same networks
            if benign_net != malicious_net:
                #identify the model's path
                path = f"./Models/{type_of_execution}/{benign_net}_B/{malicious_net}_M/"

                #get the list of the pkl files to load
                models_path= [path + f for f in listdir(path) \
                if isfile(join(path, f)) and f.endswith(".pkl")]

                #get csvs paths
                benign_path = get_csvs(type_of_execution = DATASET,
                    network = benign_net,
                    benign = True,
                    test = True)

                malicious_paths = get_csvs(type_of_execution = DATASET,
                    network = malicious_net,
                    benign = False,
                    test = True)


                #iterate over the attacks
                for curr_attack in models_path:
                    #extract the attack name from the model path
                    curr_attack_name = get_attack_name_from_model(curr_attack)

                    #select the malicious csv
                    try:
                        curr_malicious_path = [x for x in malicious_paths if curr_attack_name == get_attack_name_from_csv(x)][0]
                    except:
                        curr_malicious_path = [x for x in malicious_paths if curr_attack_name == x.split('/')[-1][:-4].split("_")[1]]
                        raise Exception(f"Attack:{curr_attack_name}\n{malicious_paths}\n{curr_malicious_path}")

                    #load the classifier
                    with open(curr_attack, 'rb') as fid:
                        clf = cPickle.load(fid)

                    #define the csv
                    te_paths = [benign_path, curr_malicious_path]
                    df_test = pd.concat([pd.read_csv(f, low_memory = False) for f in te_paths])

                    #define X and Y
                    X_test = df_test[X_features]
                    Y_test = df_test[Y_features].tolist()

                    #evaluate the test
                    y_test_pred = clf.predict(X_test)

                    #evaluation
                    test_f1 = f1_score(Y_test, y_test_pred, average = 'macro')
                    test_prec = precision_score(Y_test, y_test_pred)
                    test_recall = recall_score(Y_test, y_test_pred)
                    tn, fp, fn, tp = confusion_matrix(Y_test, y_test_pred).ravel()

                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "F1", test_f1]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "Precision", test_prec]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "Recall", test_recall]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "TN", tn]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "TP", tp]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "FN", fn]
                    res_df.loc[len(res_df)] = [benign_net, malicious_net, curr_attack_name, "FP", fp]

        print(f"\t--->cycle terminated.\n\n")

    return res_df

def run_similarity(networks, X_features, Y_features, type_of_execution):
    """ in the similarity performance, both benign and malicious samples are collected
    on the same networking evironment """
    #define the dataset with the results
    res_df = pd.DataFrame(None, columns = ["SrcNetwork", "TrgNetwork", "Attack", "Metric", "Score"])

    #start evaluation
    for ref_net in networks: #iterate over the referent networks
        print(f"\n\nStart evaluating {ref_net}")

        #we need to load all of the models we trained in the referent network
        #this can be seen as our own network. Can we sucessfully detect samples
        #of third parties networks>
        #identify the model's path
        path = f"./Models/{type_of_execution}/{ref_net}_B/{ref_net}_M/"

        #get the list of the pkl files to load
        models_path= [path + f for f in listdir(path) \
        if isfile(join(path, f)) and f.endswith(".pkl")]

        #load the ensamble
        ensamble = {}
        for i, m in enumerate(models_path):
            #load the model
            with open(m, 'rb') as fid:
                ensamble[i] = cPickle.load(fid)

        #iterate over the malicious networks
        for target_net in networks:
            #we avoid the "diagonal" --> same networks
            if ref_net != target_net:
                #get csvs paths: in this case we need both training and testing sets
                benign_path_test = get_csvs(type_of_execution = DATASET,
                    network = ref_net,
                    benign = True,
                    test = True)

                malicious_paths_test = get_csvs(type_of_execution = DATASET,
                    network = target_net,
                    benign = False,
                    test = True)


                #iterate over the attacks in the target netwotk
                for curr_malicious_path_test in malicious_paths_test:
                    # #extract the attack name from the model path
                    curr_attack_name = get_attack_name_from_csv(curr_malicious_path_test)
                    #
                    # #select the malicious csv
                    # try:
                    #     curr_malicious_path = [x for x in malicious_paths_test if curr_attack_name == get_attack_name_from_csv(x)][0]
                    # except:
                    #     curr_malicious_path = [x for x in malicious_paths_test if curr_attack_name == get_attack_name_from_csv(x)]
                    #     raise Exception(f"Attack:{curr_attack_name}\n{malicious_paths_test}\n{curr_malicious_path}")


                    #define the csv: train and test
                    te_paths = [benign_path_test, curr_malicious_path_test]
                    df_test = pd.concat([pd.read_csv(f, low_memory = False) for f in te_paths])
                    tr_paths = [x.replace("test_", "train_") for x in te_paths]
                    df_train = pd.concat([pd.read_csv(f, low_memory = False) for f in tr_paths])

                    #define X and Y
                    X_train = df_train[X_features]
                    Y_train = df_train[Y_features].tolist()

                    X_test = df_test[X_features]
                    Y_test = df_test[Y_features].tolist()

                    #find the best model index based on the training set
                    best_idx = -1
                    best_f1 = -1
                    for model_idx in range(len(ensamble)):
                        y_train_pred = ensamble[model_idx].predict(X_train)
                        curr_performance = f1_score(Y_train, y_train_pred, average = 'macro')

                        if curr_performance > best_f1:
                            best_f1 = curr_performance
                            best_idx = model_idx

                    #evaluate the test
                    y_test_pred = ensamble[best_idx].predict(X_test)

                    #evaluation
                    test_f1 = f1_score(Y_test, y_test_pred, average = 'macro')
                    test_prec = precision_score(Y_test, y_test_pred)
                    test_recall = recall_score(Y_test, y_test_pred)
                    tn, fp, fn, tp = confusion_matrix(Y_test, y_test_pred).ravel()

                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "F1", test_f1]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "Precision", test_prec]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "Recall", test_recall]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "TN", tn]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "TP", tp]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "FN", fn]
                    res_df.loc[len(res_df)] = [ref_net, target_net, curr_attack_name, "FP", fp]

        print(f"\t--->cycle terminated.\n\n")

    return res_df

if __name__ == '__main__':
    #load the parsed arguments
    args = parser.parse_args()
    TASK = args.task
    DATASET = args.dataset

    if TASK not in ["baseline", "extendibility", "similarity"]:
        raise Exception("Invalid task")

    if DATASET not in ["hom", "nonhom"]:
        raise Exception("Invalid dataset")

    inp = input(f"XeNID execution over:\n\t-->Task={TASK}\n\t-->Dataset={DATASET}\
        \n\tpress Yes to continue:\t")

    if inp.lower() == "y" or inp.lower() == "y":
        print("\n\nStart the execution ...")

        #define the csv path name
        csv_filename = f"./Results/{TASK}__{DATASET}.csv"
        print(f"\nFile with the results={csv_filename}")

        #get the dataset names
        networks = get_dataset_name(type_of_execution = DATASET)

        #get csv features name. note that this is required only because the names
        #of the two dataset versions are different
        X_features, Y_features = get_target_features_name(type_of_execution = DATASET)

        if TASK == 'baseline':
            ds_results = run_baseline(networks = networks, X_features = X_features,
                Y_features = Y_features, type_of_execution = DATASET)

        elif TASK == 'extendibility':
            ds_results = run_extendibility(networks = networks, X_features = X_features,
                Y_features = Y_features, type_of_execution = DATASET)

        elif TASK == 'similarity':
            ds_results = run_similarity(networks = networks, X_features = X_features,
                Y_features = Y_features, type_of_execution = DATASET)

        else:
            raise Exception(f"Invalid mode. The mode={TASK} might not be implemented yet")


        #save the results
        ds_results.to_csv(csv_filename)
