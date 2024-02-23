from django.shortcuts import render ,HttpResponse
from django.http import JsonResponse
import joblib ,requests
from scipy.sparse import csr_matrix
import base64,io
import seaborn as sns
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
# Create your views here.
def test(request):
    return HttpResponse("helllo")

def main(request):
    return render(request,'index.html')

# @api_view(['GET', 'POST'])
def alert(request):
    return render(request,"alerts.html")


# Load the model and vectorizer during application initialization
with open("model/pickel_model.pkl", 'rb') as f1:
    lgr = joblib.load(f1)

with open("model/pickel_vector.pkl", 'rb') as f2:
    vectorizer = joblib.load(f2)


def check_vt(url_id):
    try:
        if not url_id.startswith("http://") :
            url = "http://" + url_id
            print("ch======",url)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            print("without http",url_id)
        else:
            url_id = base64.urlsafe_b64encode(url_id.encode()).decode().strip("=")
            print("with http",url_id)

        url = "https://www.virustotal.com/api/v3/urls/"+url_id

        headers = {
            "accept": "application/json",
            "x-apikey": "982ce415cf8ef4cae0c948f2eb9dddd2cb68119f7a57d5e95c5af8b66f7dcde7"
        }
        response = requests.get(url, headers=headers)
        res=response.json()
        return res
    except:
        pass


def predict_view(request):
    if request.method == 'POST':
        url = request.POST.get('url')  # Assuming you're receiving a single URL from a form field named 'url'
        whitelist = {'hackthebox.eu', 'root-me.org', 'gmail.com'}

        if url not in whitelist:
            # Transform URL using the loaded vectorizer
            x = vectorizer.transform([url])

            # Predict using the loaded model
            y_predict = lgr.predict(x)

            # Process prediction as needed
            prediction = y_predict[0]
            if prediction in ["Bad","bad" ,"BAD"]:
                data = check_vt(url)
                if data:
                    last_analysis_results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                    # print("0909-90-9", last_analysis_results)
                    # Mapping of result strings to numerical values
                    result_mapping = {"clean": 1, "malicious": 0, "suspicious": 0, "undetected": 0, "unrated": 0}

                    engine_results = {}
                    for engine, result in last_analysis_results.items():  # Iterate over last_analysis_results.items()
                        category = result["category"]
                        if category not in engine_results:
                            engine_results[category] = []
                        engine_results[category].append(result_mapping[result["result"]])

                    # Calculating the average for each category
                    average_results = {category: sum(results) / len(results) for category, results in engine_results.items()}


                    # Creating a DataFrame for the heatmap
                    df = pd.DataFrame.from_dict(average_results, orient='index', columns=['Average'])

                    # Plotting the heatmap
                    plt.figure(figsize=(6, 4))
                    sns.heatmap(df, annot=True, cmap="PiYG", fmt=".2f")
                    plt.title('Average Analysis Results')
                    plt.xlabel('Average Result')
                    plt.ylabel('Category')
                    plt.tight_layout()

                    # Saving the plot to a buffer
                    buffer = io.BytesIO()
                    plt.savefig(buffer, format='png')
                    plt.close()

                    # Convert the image to base64
                    heatmap = base64.b64encode(buffer.getvalue()).decode()
                    ##############################################
                    last_analysis_stats = data['data']['attributes']['last_analysis_stats']

                    ######################################################################
                    malicious = data['data']['attributes']['last_analysis_stats']['malicious']
                    xcitium_category = data["data"]["attributes"]["categories"].get("Xcitium Verdict Cloud")
                    alphaMountain_category = data["data"]["attributes"]["categories"].get("alphaMountain.ai")
                    forcepoint_category = data["data"]["attributes"]["categories"].get("Forcepoint ThreatSeeker")

                    threat_names = data['data']['attributes']['threat_names']
                    url = data['data']['attributes']['url']
                    sha256_value = data['data']['attributes']['last_http_response_content_sha256']


                                     
                    return render(request, 'input_form.html',{"heatmap":heatmap,'xcitium_category':xcitium_category,
                                                              'alphaMountain_category':alphaMountain_category,
                                                              'forcepoint_category':forcepoint_category,
                                                              'threat_names':threat_names,'url':url,
                                                               'sha256':sha256_value ,
                                                               'malicious':malicious,
                                                               'last_analysis_stats':last_analysis_stats})

            else:
                return render(request, 'input_form.html',{"data":"url not exists"})
    else:
        return render(request, 'input_form.html')
