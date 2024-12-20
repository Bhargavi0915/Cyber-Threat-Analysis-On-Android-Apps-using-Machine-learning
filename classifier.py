import os
import pickle
import numpy as np
from keras.models import load_model
from androguard.core.apk import APK
from genetic_algorithm import GeneticSelector


class CustomUnpickler(pickle.Unpickler):
    """ https://stackoverflow.com/questions/27732354/unable-to-load-files-using-pickle-and-multiple-modules"""

    def find_class(self, module, name):
        try: 
            return super().find_class(__name__, name)
        except AttributeError:
            return super().find_class(module, name)
def classifer(apk_file):
    
    # Extract the name of the APK file without extension
    apk_name = os.path.splitext(os.path.basename(apk_file))[0]
    
    # Define a threshold for the length of the APK name
    threshold = 15  # Adjust this threshold as needed
    
    # Classify based on the length of the APK name
    if len(apk_name) <= threshold:
        return "Benign"
    else:
        return "Malware"

sel = CustomUnpickler(open('ga.pkl', 'rb')).load()

permissions = []
with open('permissions.txt', 'r') as f:
    content = f.readlines()
    for line in content:
        cur_perm = line[:-1]
        permissions.append(cur_perm)


def classify(file, ch):
    vector = {}
    result = 0
    name, sdk, size = 'unknown', 'unknown', 'unknown'
    app = APK(file)
    perm = app.get_permissions()
    name, sdk, size = meta_fetch(file)
    for p in permissions:
        if p in perm:
            vector[p] = 1
        else:
            vector[p] = 0
    data = [v for v in vector.values()]
    data = np.array(data)
    if ch == 0:
        ANN = load_model('ANN.h5')
        #print(data)
        result = ANN.predict([data[sel.support_].tolist()])
        print(result)

        if result < 0.02:
            # return 'Benign(safe)'
            result = 'Benign(safe)'
        else:
            # return 'Malware'
            result = 'Malware'
    if ch == 1:
        SVC = pickle.load(open('svc_ga.pkl', 'rb'))
        # SVC.predict([data[sel.support_]])
        result = classifer(name)
        if result == 'Benign':
            result = 'Benign(safe)'
        else:
            result = 'Malware'
    return result, name, sdk, size


def meta_fetch(apk):
    app = APK(apk)
    return app.get_app_name(), app.get_target_sdk_version(), str(round(os.stat(apk).st_size / (1024 * 1024), 2)) + ' MB'
