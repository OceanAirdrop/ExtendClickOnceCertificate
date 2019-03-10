# ExtendClickOnceCertificate

This project allows you to "renew" your existing ClickOnce certificate and give it a longer expiry date.  It extends Click Once Certs By 105 years!!!

This code was originally provided by Microsoft and then modified by Cliff Stanford who updated it to add 5 years to the expiry date.

http://may.be/renewcert/

Then Nathan Jones Ported the C++ code to C#.

https://nathanpjones.com/2013/01/renewing-temporary-certificate/

I have created this project on Github and also extended the expiry date by 105 years. 

Fully tested and confirmed it works.

# More Information:

https://stackoverflow.com/questions/280472/how-can-i-renew-my-expired-clickonce-certificate
https://robindotnet.wordpress.com/2010/01/26/how-to-extend-an-existing-certificate-even-if-it-has-expired/

# Usage:

renewcert <PFX File> <new cert filename> <new cert friendly name> (<password>)



