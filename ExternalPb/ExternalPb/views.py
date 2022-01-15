from django.http import HttpResponse
import requests
import json

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
        customerID = request.POST.get('CustomrID').strip()

        request.session['loginID'] = username
        request.session['password'] = password
        request.session['CustomrID'] = customerID

    credentials, customerDetail = getCredentials(request.session['CustomrID'])
    if credentials[0] == request.session['loginID'] and credentials[1] == request.session['password']:
        authenticated_var = True
        return render(request, 'customerPortal/index.html', {
            'detail': customerDetail,
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