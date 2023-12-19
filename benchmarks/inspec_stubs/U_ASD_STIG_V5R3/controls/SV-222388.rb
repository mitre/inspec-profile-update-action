control 'SV-222388' do
  title 'The application must clear temporary storage and cookies when the session is terminated.'
  desc 'Persistent cookies are a primary means by which a web application will store application state and user information.  Since HTTP is a stateless protocol, this persistence allows the web application developer to provide a robust and customizable user experience.

However, if a web application stores user authentication information within a persistent cookie or other temporary storage mechanism, this information can be stolen and used to compromise the users account.

Likewise, HTML 5 provides the developer with a client storage capability where application data larger than the 4K cookie size limit can be stored on the local client.  While this can be beneficial to the developer, this is considered insecure storage and should not be used for storing sensitive session or security tokens.  A cross site scripting attack can put this data at risk.

Web applications must clear sensitive data from files and storage areas on the client when the session is terminated.'
  desc 'check', 'Review application design documentation and interview application administrator to identify how the application makes use of temporary client storage and cookies.  Identify cookie and web storage locations on the client.  Clear all browser cookies and web cache.

Log on to the application and perform several standard operations, noting if the application ever prompts the user to accept a cookie. If prompted by the browser to save the user ID and password (decline to save the user ID and password), this is a finding. 

Log out of the application and close the browser. Reopen the browser and examine the stored cookies. The cookies displayed should be related to the application website.

The procedure to view cookies will vary according to the browser used. Some modern browsers are making use of SQLite databases to store cookie data so use of a SQLite db reader/browser may be required.

Open the cookies related to the application website and search for any identification or authentication information. While authentication information can vary on a per application basis, this is most often specified as "username=x", or "password=x".

If the web application prompts the user to save their password, or if a username or password value exists within a cookie or within local storage locations, even if hashed, this is a finding.

The application may use means other than cookies to store user information. If the reviewer detects an alternative mechanism for storing information locally, examine the data storage to ensure no authentication or other sensitive information is present.'
  desc 'fix', 'Design and configure the application to clear sensitive data from cookies and local storage when the user logs out of the application.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24058r493072_chk'
  tag severity: 'medium'
  tag gid: 'V-222388'
  tag rid: 'SV-222388r879673_rule'
  tag stig_id: 'APSC-DV-000060'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-24047r493073_fix'
  tag 'documentable'
  tag legacy: ['SV-83863', 'V-69241']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
