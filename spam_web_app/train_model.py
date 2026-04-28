"""Train a more robust spam classifier and save model.pkl + vectorizer.pkl."""
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from text_utils import preprocess

DIR = Path(__file__).resolve().parent

# Stronger synthetic corpus with more realistic spam and ham patterns.
HAM = [
    "Meeting scheduled for Tuesday at 3pm conference room",
    "Please find the quarterly report attached for your review",
    "Thanks for your help with the project last week",
    "Lunch tomorrow at the usual place let me know if you can make it",
    "The code review comments have been addressed in the latest commit",
    "Happy birthday hope you have a wonderful day",
    "Flight confirmation your trip to Seattle on March 15",
    "Reminder dentist appointment next Thursday morning",
    "Can we reschedule our call to Friday afternoon",
    "The package was delivered to your front door",
    "Team sync notes from yesterday are in the shared doc",
    "Invoice 1042 has been paid thank you",
    "Your subscription renews next month no action needed",
    "Great work on the presentation the client loved it",
    "Weather looks nice this weekend want to go hiking",
    "Here are the notes from standup today nothing urgent",
    "The design mockups are in Figma for review when you have time",
    "Kids soccer practice moved to Saturday morning same field",
    "Please approve the expense report by end of week thanks",
    "Library books due next Monday renewal available online",
    "Your order shipped and should arrive tomorrow morning",
    "The seminar agenda is attached for the client call next week",
    "Send me your availability for a quick planning session",
    "The monthly budget update is ready for distribution",
    "Our leadership meeting is confirmed for Friday afternoon",
    "Please review the attached legal agreement before signing",
]

SPAM = [
    "Congratulations you won the lottery claim your prize now click here",
    "URGENT act now limited time offer buy viagra cheap pills",
    "You have been selected for a free iPhone click this link",
    "Make money fast from home earn 5000 dollars per day guaranteed",
    "Your account will be suspended verify your password immediately",
    "Nigerian prince needs your help transfer funds wire money",
    "Hot singles in your area click now meet tonight",
    "You are a winner claim your reward send bank details",
    "Free gift card click here before offer expires act fast",
    "Debt consolidation approved no credit check apply now",
    "Lose weight fast miracle pill doctors hate this",
    "Your PayPal account limited verify now or lose access",
    "Investment opportunity 300 percent returns guaranteed",
    "You inherited millions contact lawyer with your SSN",
    "Exclusive deal Viagra Cialis pharmacy no prescription",
    "Click here now or your account will be closed forever",
    "You have one new voicemail press one to listen urgent",
    "Crypto giveaway send ethereum to double your coins",
    "Work from home no experience required earn thousands weekly",
    "Your package could not be delivered pay shipping fee online",
    "Win a free vacation now by entering your credit card details",
    "Limited time discount on luxury watches buy one get one free",
    "Final notice overdue invoice payment needed to avoid collection",
    "Confirm your identity now to prevent account suspension",
    "Cheap refinance rates available even with bad credit",
    "Join our affiliate program and earn money with no experience",
    "Click the link to watch your private video message",
    "Update billing details to restore your account privileges",
    "This is your chance to join our elite program before spots fill",
    "Your social media account has been compromised verify login now",
    "Get the latest crypto alert and double your investment",
]

RAW_TEXTS = HAM + SPAM
LABELS = [0] * len(HAM) + [1] * len(SPAM)
TEXTS = [preprocess(t) for t in RAW_TEXTS]


def main():
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=False,
                    stop_words="english",
                    max_df=0.85,
                    min_df=2,
                    max_features=10000,
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=3000,
                    random_state=42,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )
    pipeline.fit(TEXTS, LABELS)

    vectorizer = pipeline.named_steps["tfidf"]
    model = pipeline.named_steps["clf"]

    joblib.dump(model, DIR / "model.pkl")
    joblib.dump(vectorizer, DIR / "vectorizer.pkl")
    print("Saved model.pkl and vectorizer.pkl to", DIR)


if __name__ == "__main__":
    main()
