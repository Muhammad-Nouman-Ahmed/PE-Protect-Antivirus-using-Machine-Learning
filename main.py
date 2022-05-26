import webbrowser
from threading import Timer
import os
from flask import *
from antivirus import *
import pickle
import joblib
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import os

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'uploads')
ALLOWED_EXTENSIONS = {'exe'}

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

dir = UPLOAD_FOLDER
for f in os.listdir(dir):
    os.remove(os.path.join(dir, f))

app = Flask(__name__)
app.secret_key = 'nouman'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def upload():
    return render_template("index.html")

@app.route('/result', methods=['POST'])
def upload1():
    print('Detect malicious files')
    root=Tk()
    root.attributes('-topmost', 1)
    Tk().withdraw()
    filename = askopenfilename()
    print(filename)
    target = filename
    root.destroy()
    # Load classifier
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'
    ))

    print(clf)
    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read()
    )
    print(features)

    data = extract_infos(filename)

    pe_features = list(map(lambda x: data[x], features))

    res = clf.predict([pe_features])[0]
    
    print('The file %s is %s' % (
        os.path.basename(filename),
        ['malicious', 'legitimate'][res])
    )
    return render_template("result.html", disp=os.path.basename(filename), disp1=['malicious', 'legitimate'][res], disp2=clf, disp3=features)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def open_browser():
    webbrowser.open_new('http://127.0.0.1:2000/')


if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(port=2000, debug=True, threaded=True, use_reloader=False)