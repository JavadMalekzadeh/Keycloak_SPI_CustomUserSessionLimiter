# Keycloak_SPI_CustomUserSessionLimiter

A new Keycloak limiter addon has been proposed to reject or terminate sessions when a user attempts to log in with the same username and password from different IP addresses. Security is a critical aspect of applications globally, and the authorization server plays a crucial role in the overall security framework by providing features that allow users to authenticate effectively. One such feature in Keycloak is the limitation on the number of login attempts. Limiting user logins based on IP addresses is an essential security measure to prevent unauthorized access and potential security breaches.
Here’s a high-level approach to implementing security measures in Keycloak:
1. **Track IP Addresses :**  Store the IP address of each user upon login. In Keycloak, the IP address can be saved along with the session for every login action.
![Untitsdsled](https://github.com/user-attachments/assets/cbb1a7b7-db74-41ed-b426-81b23c3a5655)

2. **IP Check :** For subsequent login attempts, verify whether the request is coming from the same IP address as the previous session. Keycloak includes a default user session count limiter that can be configured to control the number of concurrent sessions a single user is allowed to create for a specific realm or client. This provider can be overridden and extended to consider not just sessions but also other parameters that may indicate potential security breaches, such as IP addresses.

3. **Handle IP Mismatch :** If an IP mismatch occurs, various security measures can be implemented, including:
   - Denying the login attempt while allowing the old session to persist.
   - Terminating the old session and generating a new session for the recent login.
   - Sending an alert to the user.
   - Requesting additional verification, such as two-factor authentication (2FA).

By following this approach, Keycloak can enhance its security protocols and better protect user accounts.

To create a new user session count limiter provider, we have implemented the `Authenticator` interface. This approach considers two security measures for login validation: `User` Alone, and `User & IP`. Additionally, the number of sessions a user can maintain may still exceed one, depending on the configuration that the user sets after adding the provider to their authentication flow.
![Untitledfd](https://github.com/user-attachments/assets/c30be682-caa4-4857-81ba-d2fc48328bc1)
