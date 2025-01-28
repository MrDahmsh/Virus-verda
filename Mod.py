##ملف advanx
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

# إنشاء نموذج ذكاء اصطناعي بسيط
def create_advanced_ai():
    model = Sequential()
    model.add(Dense(128, input_dim=100, activation='relu'))  # طبقة إدخال
    model.add(Dropout(0.3))  # إسقاط عشوائي
    model.add(Dense(256, activation='relu'))  # طبقة خفية
    model.add(Dropout(0.3))
    model.add(Dense(512, activation='relu'))  # طبقة قوية
    model.add(Dense(1, activation='sigmoid'))  # طبقة إخراج

    # إعداد النموذج
    model.compile(optimizer=Adam(learning_rate=0.0001),
                  loss='binary_crossentropy',
                  metrics=['accuracy'])
    return model

# إنشاء النموذج وتخزينه
model = create_advanced_ai()
model.save("advanced_ai.h5")
print("تم إنشاء ملف advanced_ai.h5 بنجاح!")
