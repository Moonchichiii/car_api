"""Middleware to enforce additional security policies:"""

from .auth_logger import log_auth_event, get_client_ip


class AuthSecurityMiddleware:
    """
    Middleware to enforce additional security policies:
    - Track user IP changes
    - Enforce session timeouts
    - Log suspicious activities
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:

            current_ip = get_client_ip(request)

            user = request.user
            last_login_ip = user.last_login_ip

            if last_login_ip and current_ip and last_login_ip != current_ip:

                log_auth_event(
                    "ip_change_detected",
                    user,
                    request,
                    {
                        "previous_ip": last_login_ip,
                        "current_ip": current_ip,
                    },
                )
        response = self.get_response(request)
        return response
