FROM python:3.8
ADD . /code
WORKDIR /code
EXPOSE 5000
RUN pip3 install -r requirements.txt
CMD [ "python3", "app.py"]