import json
from ..util.http_crypto_helper import HttpCryptoHelper
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def test_controller(request):
    request_params = json.loads(request.body.decode("utf-8"))

    helper = HttpCryptoHelper()

    request_data = helper.decrypt_request_data(request_params)

    print(request_data)

    return HttpResponse(helper.encrypt_response_data({
        "success": True,
        "msg": ""
    }))
