control 'SV-18865' do
  title 'Classified videoconferencing systems must authenticate with a unique user logon prior to performing functions and services.'
  desc "DoD policy requires users to authenticate prior to being authorized to use available services. While requiring a user to authenticate to the video endpoint before it can be used to make or receive calls may detract from the video endpoint's “ease of use” and the “user experience” the capability should exist, be used where needed, and be configurable. Users should authenticate to activate the video endpoint for general use, make a call, or answer a call. Minimally, authentication should be a password unique to the user and recorded in session logs. Preferably, the video endpoint should support the use of DoD PKI for user authentication. To comply with DoD access control requirements for both users and administrators, a video endpoint should use a remote authentication server that can provide centralized management of passwords and accounts. This controls access to the videoconferencing system and limits the user’s privileges or authorizations. Many videoconferencing endpoints today do not provide sufficient identification, authorization, or auditing capabilities regarding their activation and use. While at least one vendor’s system can be configured to require the entry of a PIN to place a call, the feature is only a call accounting feature and not a security feature. While gatekeepers and gateways provide some access control, this control only relates to access to their services. They do not play a part in endpoint activation or use of the endpoint for point-to-point calls. 

The ITU developed H.235 as the security recommendation for H.323 and other H.245-based systems. H.323 provides for user identification rather than device identification, using simple passwords/PINs or DoD PKI. H.235 has the capability of negotiating encryption and key exchange. The use of H.350 can improve security by providing standardized management and storage of authentication credentials, as well as multilevel authorization. The use of H.245 and H.350 in combination could be the solution to the endpoint activation and user identification deficiency currently exhibited by videoconferencing endpoints. 

While it seems debatable whether a videoconferencing endpoint is, or should be, subject to DoD access control and auditing policies, particularly in unclassified environments, there are use cases where such compliance would be beneficial to the protection of DoD information. This is particularly in cases where a video endpoint is located in an area where classified materials, information, or discussions occur because an active video endpoint could generate a security incident. This issue could be more of a concern if the video endpoint was located in a classified work area while connected to an unclassified network or network having a lower classification than the work area. Compliance would also be beneficial for video endpoints in areas processing sensitive information. To protect the information, the video endpoint should remain dormant (even while powered on) and not capable of placing or answering a call unless it is activated by a user logging onto the system."
  desc 'check', 'Review site documentation to confirm the classified videoconferencing system authenticates using a unique user logon prior to performing functions and services. The video endpoint must not be capable of placing or answering a call unless it is unlocked by a user logon. Additionally, ensure the video endpoint configuration settings are as follows:
- Unique (non-default/non-shared) IDs for each privileged and user account, to include an administrator test account. Note this is best accomplished using a central user management system, such as RADIUS or TACACS+. Authentication must meet current DoD requirements and may implement username/password or multifactor authentication (DoD PKI token preferred).
- Video endpoints to require unique user identities to authenticate at first logon and when unlocking. 
- Video endpoints to automatically lock after 15 minutes of inactivity.
- Video endpoints to display incoming call notifications while locked (a unique ID is required to activate the video endpoint and answer the call).

If the classified videoconferencing system is not configured as above, this is a finding. If the classified videoconferencing system does not authenticate using a unique user logon prior to performing functions and services, this is a finding.'
  desc 'fix', 'Configure the classified videoconferencing system to authenticate with a unique user logon prior to performing functions and services. Additionally, configure the video endpoint with the following:
- Configure unique (non-default/non-shared) IDs for each privileged and user account, to include an administrator test account. Note this is best accomplished using a central user management system, such as RADIUS or TACACS+. Authentication must meet current DoD requirements and may implement username/password or multifactor authentication (DoD PKI token preferred).
- Configure video endpoints to require unique user identities to authenticate at first logon and when unlocking. 
- Configure video endpoints to automatically lock after 15 minutes of inactivity.
- Configure video endpoints to display incoming call notifications while locked (a unique ID is required to activate the video endpoint and answer the call).'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18961r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17691'
  tag rid: 'SV-18865r2_rule'
  tag stig_id: 'RTS-VTC 2028.00'
  tag gtitle: 'RTS-VTC 2028'
  tag fix_id: 'F-17588r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
