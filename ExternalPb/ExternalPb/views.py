from django.http import HttpResponse
import requests
import json
from django.conf import settings
from django.shortcuts import render, redirect

api_hostname = '103.251.120.243'
api_base = 'https://%s/rest/' % api_hostname
authenticated_var = False


def getSession(customerID):
    api_user = 'shaun'
    api_password = '@##$#gurdianofadn461*#?'

    arr_credential = []
    customerDetails = []

    # for self-signed certificates
    requests.packages.urllib3.disable_warnings()

    # login
    req_data = {'params': json.dumps({'login': api_user, 'password': api_password})}
    r = requests.post(api_base + 'Session/login', data=req_data, verify=False)
    data = r.json()
    session_id = data['session_id']

    return session_id


def getCustomerInfo(customerID):
    session_id = getSession(customerID)
    # get currency list
    req_data = {'auth_info': json.dumps({'session_id': session_id}), 'params': json.dumps({
        'detailed_info': 1,
        'get_auth_info': 1,
        'i_customer': customerID,
    })}
    r = requests.post(api_base + 'Customer/get_customer_info', data=req_data, verify=False)
    data = r.json()
    return data


def getCredentials(customerID):
    arr_credential = []
    customerDetails = []

    # for self-signed certificates
    requests.packages.urllib3.disable_warnings()

    data = getCustomerInfo(customerID)

    login = data['customer_info']['login']
    arr_credential.append(login)
    password = data['customer_info']['password']
    arr_credential.append(password)

    customerDetails.append(data['customer_info']['balance'])
    customerDetails.append(data['customer_info']['credit_limit'])
    customerDetails.append(data['customer_info']['i_customer'])
    customerDetails.append(data['customer_info']['i_balance_control_type'])

    if customerDetails[3] == 2:
        customerDetails[0] = customerDetails[0] * -1

    return arr_credential, customerDetails


def makePayment(request):
    if request.method == 'POST':
        amount = request.POST.get('amount').strip()
        customerID = request.POST.get('customerID').strip()
        # print(username)
        # print(customerID)
        # print(amount)
        customerDetails = []

        session_id = getSession(customerID)

        # make payment
        req_data = {'auth_info': json.dumps({'session_id': session_id}), 'params': json.dumps({
            'action': 'Manual payment',
            'amount': amount,
            'internal_comment': 'Customer Payment',
            'i_customer': customerID,
        })}
        r = requests.post(api_base + 'Customer/make_transaction', data=req_data, verify=False)
        data = r.json()

        customerInfo = getCustomerInfo(customerID)
        customerDetails.append(customerInfo['customer_info']['balance'])
        customerDetails.append(customerInfo['customer_info']['credit_limit'])
        customerDetails.append(customerInfo['customer_info']['i_customer'])
        customerDetails.append(customerInfo['customer_info']['i_balance_control_type'])

        if customerDetails[3] == 2:
            customerDetails[0] = customerDetails[0] * -1
        # balance = data['balance']

        return render(request, 'customerPortal/index.html', {
            'detail': customerDetails,
        })


def login(request):
    global authenticated_var
    if request.method == 'POST':
        username = request.POST.get('loginID').strip()
        password = request.POST.get('password').strip()
        customerID = request.POST.get('CustomerID').strip()

        request.session['loginID'] = username
        request.session['password'] = password
        request.session['CustomerID'] = customerID

    paymentID, token = getApiCredentials()
    if 'CustomerID' in request.session:
        credentials, customerDetail = getCredentials(request.session['CustomerID'])
        if credentials[0] == request.session['loginID'] and credentials[1] == request.session['password']:
            authenticated_var = True
            return render(request, 'customerPortal/index.html', {
                'detail': customerDetail,
                'paymentID': paymentID,
                'token': token,
            })
    else:
        # request.user.is_authenticated = False
        return render(request, 'error/noUser.html', {
            'status': 'notLoggedIn',
        })


def loginPage(request):
    global authenticated_var
    if authenticated_var:
        return redirect('home')
    else:
        return render(request, 'login.html')


def logout(request):
    global authenticated_var
    authenticated_var = False

    del request.session['loginID']
    del request.session['password']
    del request.session['CustomrID']

    return HttpResponse("logged out!")


def downloadXdr(request):
    return HttpResponse("download xdr")


def getApiCredentials():
    url = "https://checkout.sandbox.bka.sh/v1.2.0-beta/checkout/token/grant"

    payload = {
        "app_key": "5nej5keguopj928ekcj3dne8p",
        "app_secret": "1honf6u1c56mqcivtc9ffl960slp4v2756jle5925nbooa46ch62"
    }
    headers = {
        "Accept": "application/json",
        "username": "testdemo",
        "password": "test%#de23@msdao",
        "Content-Type": "application/json"
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    data = response.json()
    token = data['id_token']

    # payment create
    url = "https://checkout.sandbox.bka.sh/v1.2.0-beta/checkout/payment/create"

    payload = {
        "amount": "90",
        "currency": "BDT",
        "intent": "sale",
        "merchantInvoiceNumber": "202098957723"
    }
    headers = {
        "Accept": "application/json",
        "X-APP-Key": "5nej5keguopj928ekcj3dne8p",
        "Content-Type": "application/json",
        "Authorization": token
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    data = response.json()
    paymentID = data['paymentID']

    return paymentID, token
