from django.shortcuts import render
import json
import re
import numpy as np
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .feature_extractor import extract_features
from .HybridModel.predictor import predict
from django.shortcuts import render, redirect


def goaway(request):
    return render(request, 'goaway.html')

def normalize_url(url):
    url = str(url).strip()
    url = url.strip("'\"")
    if not url or url.lower() == 'nan' or len(url) < 4:
        return None
    url = re.sub(r'\[\.\]', '.', url)
    url = re.sub(r'hxxps?://', 'http://', url)
    url = re.sub(r'^https?://https?:\s*//', 'http://', url)
    url = url.replace(' ', '')
    try:
        url.encode('ascii')
    except UnicodeEncodeError:
        if not url.startswith(('http://', 'https://')) or \
           sum(ord(c) > 127 for c in url) > 5:
            return None
    if url.startswith('https://'):
        url = 'http://' + url[8:]
    elif not url.startswith('http://'):
        url = 'http://' + url
    return url

@csrf_exempt
def analyze(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    try:
        body = json.loads(request.body)
        url  = body.get("url")

        if not url:
            return JsonResponse({"error": "No URL provided"}, status=400)

        normalized = normalize_url(url)
        if normalized is None:
            return JsonResponse({"error": "Invalid URL"}, status=400)

        features = extract_features(normalized)
        if features is None:
            return JsonResponse({"error": "Feature extraction failed"}, status=400)

        result = predict(normalized, features)
        if result is None:
            return JsonResponse({"error": "Prediction failed"}, status=500)

        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def health(request):
    return JsonResponse({"status": "ok"})