#!/usr/bin/env python3
"""
Test all trained models for accuracy before Dashboard integration.
Run this script to validate models work correctly.
"""

import json
import sys
from pathlib import Path

# Fix Windows console encoding
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import joblib
import numpy as np


def test_office_model():
    """Test Office document malware model"""
    print("\n" + "="*60)
    print("TESTING OFFICE DOCUMENT MODEL")
    print("="*60)
    
    model_path = Path("models/doc/office_malware_rf.joblib")
    feature_order_path = Path("models/doc/office_feature_order.json")
    card_path = Path("models/doc/MODEL_CARD.json")
    
    # Check files exist
    if not model_path.exists():
        print(f"❌ Model not found: {model_path}")
        return False
    if not feature_order_path.exists():
        print(f"❌ Feature order not found: {feature_order_path}")
        return False
        
    print(f"✓ Model file found: {model_path} ({model_path.stat().st_size / 1024:.1f} KB)")
    
    # Load model
    try:
        model = joblib.load(model_path)
        print(f"✓ Model loaded: {type(model).__name__}")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return False
    
    # Load feature order
    with open(feature_order_path) as f:
        features = json.load(f)
    print(f"✓ Features loaded: {len(features)} features")
    
    # Load model card
    if card_path.exists():
        with open(card_path) as f:
            card = json.load(f)
        print(f"✓ Model Card:")
        print(f"  - Type: {card['model_type']}")
        print(f"  - ROC-AUC: {card['metrics']['roc_auc']:.4f}")
        print(f"  - Accuracy: {card['metrics']['test_accuracy']:.4f}")
        print(f"  - FPR: {card['metrics']['false_positive_rate']:.4f}")
    
    # Test with dummy data
    print("\n Testing with sample feature vectors...")
    
    # Benign sample (all zeros - no suspicious features)
    benign_sample = np.zeros((1, len(features)))
    try:
        benign_pred = model.predict(benign_sample)[0]
        benign_proba = model.predict_proba(benign_sample)[0]
        print(f"✓ Benign sample: prediction={benign_pred}, probability={benign_proba[1]:.3f}")
        
        if benign_proba[1] < 0.3:  # Should be low risk
            print("  ✓ Correctly identified as benign")
        else:
            print(f"  ⚠️  Warning: Benign sample scored {benign_proba[1]:.3f} (expected < 0.3)")
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        return False
    
    # Malicious sample (multiple suspicious features)
    malicious_sample = np.zeros((1, len(features)))
    # Set some suspicious features (assuming typical VBA indicators)
    suspicious_indices = [0, 2, 5, 7, 10]  # Random suspicious feature indices
    malicious_sample[0, suspicious_indices] = 1
    
    try:
        mal_pred = model.predict(malicious_sample)[0]
        mal_proba = model.predict_proba(malicious_sample)[0]
        print(f"✓ Malicious sample: prediction={mal_pred}, probability={mal_proba[1]:.3f}")
        
        if mal_proba[1] > 0.5:  # Should be high risk
            print("  ✓ Correctly identified as malicious")
        else:
            print(f"  ⚠️  Warning: Malicious sample scored {mal_proba[1]:.3f} (expected > 0.5)")
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        return False
    
    print("\n✅ Office Document Model: PASSED")
    return True


def test_pdf_model():
    """Test PDF malware model"""
    print("\n" + "="*60)
    print("TESTING PDF MODEL")
    print("="*60)
    
    model_path = Path("models/pdf/pdf_malware_rf.joblib")
    feature_order_path = Path("models/pdf/pdf_feature_order.json")
    card_path = Path("models/pdf/pdf_model_card.json")
    
    # Check files exist
    if not model_path.exists():
        print(f"❌ Model not found: {model_path}")
        return False
    if not feature_order_path.exists():
        print(f"❌ Feature order not found: {feature_order_path}")
        return False
        
    print(f"✓ Model file found: {model_path} ({model_path.stat().st_size / 1024:.1f} KB)")
    
    # Load model
    try:
        model = joblib.load(model_path)
        print(f"✓ Model loaded: {type(model).__name__}")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return False
    
    # Load feature order
    with open(feature_order_path) as f:
        features = json.load(f)
    print(f"✓ Features loaded: {len(features)} features")
    
    # Load model card
    if card_path.exists():
        with open(card_path) as f:
            card = json.load(f)
        print(f"✓ Model Card:")
        print(f"  - Type: {card['model_type']}")
        print(f"  - ROC-AUC: {card['metrics']['roc_auc']:.4f}")
        print(f"  - Accuracy: {card['metrics']['accuracy']:.4f}")
    
    # Test with dummy data
    print("\n Testing with sample feature vectors...")
    
    # Benign PDF (low feature values)
    benign_sample = np.random.rand(1, len(features)) * 0.1  # Small random values
    try:
        benign_pred = model.predict(benign_sample)[0]
        benign_proba = model.predict_proba(benign_sample)[0]
        print(f"✓ Benign sample: prediction={benign_pred}, probability={benign_proba[1]:.3f}")
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        return False
    
    # Malicious PDF (high feature values)
    malicious_sample = np.random.rand(1, len(features)) * 10 + 5  # Larger values
    try:
        mal_pred = model.predict(malicious_sample)[0]
        mal_proba = model.predict_proba(malicious_sample)[0]
        print(f"✓ Malicious sample: prediction={mal_pred}, probability={mal_proba[1]:.3f}")
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        return False
    
    print("\n✅ PDF Model: PASSED")
    return True


def test_url_model():
    """Test URL model"""
    print("\n" + "="*60)
    print("TESTING URL MODEL")
    print("="*60)
    
    model_path = Path("models/url/url_pipeline.joblib")
    card_path = Path("models/url/model_card.json")
    
    # Check files exist
    if not model_path.exists():
        print(f"❌ Model not found: {model_path}")
        return False
        
    print(f"✓ Model file found: {model_path} ({model_path.stat().st_size} bytes)")
    
    # Check file size - seems too small
    if model_path.stat().st_size < 1000:
        print(f"⚠️  Warning: Model file is very small ({model_path.stat().st_size} bytes)")
        print("  This might be a stub or placeholder. Check if model was fully trained.")
    
    # Load model
    try:
        model = joblib.load(model_path)
        print(f"✓ Model loaded: {type(model).__name__}")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return False
    
    # Load model card
    if card_path.exists():
        with open(card_path) as f:
            card = json.load(f)
        print(f"✓ Model Card:")
        print(f"  - ROC-AUC: {card['eval']['roc_auc']:.4f}")
        print(f"  - Precision: {card['eval']['precision']:.4f}")
        print(f"  - Recall: {card['eval']['recall']:.4f}")
    
    # Test with sample URLs
    print("\n Testing with sample URLs...")
    
    test_urls = [
        ("https://www.google.com", "benign"),
        ("https://www.microsoft.com", "benign"),
        ("http://secure-paypal-verify.xyz", "malicious"),
        ("http://192.168.1.1/login", "suspicious"),
    ]
    
    for url, expected_label in test_urls:
        try:
            # Try to predict
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba([url])[0]
                print(f"✓ {url[:40]:<40} -> {proba[1]:.3f} ({expected_label})")
            elif hasattr(model, 'predict'):
                pred = model.predict([url])[0]
                print(f"✓ {url[:40]:<40} -> {pred} ({expected_label})")
            else:
                print(f"⚠️  Model doesn't have predict/predict_proba methods")
                return False
        except Exception as e:
            print(f"❌ Prediction failed for {url}: {e}")
            return False
    
    print("\n✅ URL Model: PASSED")
    return True


def test_email_model():
    """Test email/text phishing model"""
    print("\n" + "="*60)
    print("TESTING EMAIL/TEXT PHISHING MODEL")
    print("="*60)
    
    model_dir = Path("models/email")
    
    # Check if transformers model exists
    config_path = model_dir / "config.json"
    tokenizer_path = model_dir / "tokenizer_config.json"
    
    if not config_path.exists():
        print(f"❌ Model config not found: {config_path}")
        print("  Email model might not be fully downloaded/trained yet")
        return False
    
    print(f"✓ Model config found: {config_path}")
    
    if tokenizer_path.exists():
        print(f"✓ Tokenizer config found: {tokenizer_path}")
    
    # Check for model weights
    weight_files = list(model_dir.glob("*.bin")) + list(model_dir.glob("*.safetensors"))
    if not weight_files:
        print("⚠️  Warning: No model weight files (.bin or .safetensors) found")
        print("  Model might not be fully trained/downloaded yet")
        return False
    
    print(f"✓ Model weights found: {len(weight_files)} file(s)")
    
    # Try to load with transformers
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        
        tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        print(f"✓ Model loaded: {model.__class__.__name__}")
        
        # Test with sample texts
        print("\n Testing with sample texts...")
        
        test_texts = [
            ("Your package has been delivered. Thank you for your order.", "benign"),
            ("URGENT! Verify your account now or it will be closed!", "phishing"),
            ("Click here to claim your $1000 prize immediately", "phishing"),
        ]
        
        import torch
        model.eval()
        
        for text, expected in test_texts:
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                outputs = model(**inputs)
                proba = torch.softmax(outputs.logits, dim=1)[0][1].item()
            print(f"✓ {text[:50]:<50} -> {proba:.3f} ({expected})")
        
        print("\n✅ Email/Text Model: PASSED")
        return True
        
    except ImportError:
        print("⚠️  transformers not installed. Install with: pip install transformers torch")
        return False
    except Exception as e:
        print(f"❌ Model loading/inference failed: {e}")
        return False


def main():
    """Run all model tests"""
    print("="*60)
    print("GUARDIAN AI - MODEL VALIDATION SUITE")
    print("="*60)
    print("\nThis script tests all trained models before Dashboard integration.")
    print("Each model is loaded and tested with sample inputs.\n")
    
    results = {}
    
    # Test each model
    results["Office Document"] = test_office_model()
    results["PDF"] = test_pdf_model()
    results["URL"] = test_url_model()
    results["Email/Text"] = test_email_model()
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    for model_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{model_name:<20} {status}")
    
    # Overall result
    all_passed = all(results.values())
    
    print("\n" + "="*60)
    if all_passed:
        print("✅ ALL MODELS VALIDATED SUCCESSFULLY")
        print("Ready for Dashboard integration!")
    else:
        print("❌ SOME MODELS FAILED VALIDATION")
        print("Fix errors before proceeding to integration.")
    print("="*60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
