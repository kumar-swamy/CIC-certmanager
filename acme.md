# Deploy HTTPS web application on Kubernetes with Citrix ingress controller and Let`s Encrypt using cert-manager

[Let's Encrypt](https://letsencrypt.org/docs/) and the ACME (Automatic Certificate Management Environment) protocol enables you to set up an HTTPS server and automatically obtain a browser-trusted certificate. To get a certificate for your website’s domain from Let’s Encrypt, you have to demonstrate control over the domain. Currently, there are two different challenge types, http-01 and dns-01.

A challenge is one of a list of specified tasks that only someone who controls the domain should be able to accomplish, such as:

-  **HTTP-01 challenge:** Posting a specified file in a specified location on a web site (the HTTP-01 challenge). Let's Encrypt CA verifies the file by making an HTTP request on the HTTP URI to satisfy the challenge.

-  **DNS-01 challenge:**  DNS01 challenges are completed by providing a computed key that is present at a DNS TXT record. Once this TXT record has been propagated across the internet, the ACME server can successfully retrieve this key via a DNS lookup and can validate that the client owns the domain for the requested certificate. With the correct permissions, cert-manager will automatically present this TXT record for your given DNS provider

On successful validation of the challenge, a certificate is granted for the domain.

This topic provides information on how to securely deploy an HTTPS web application on a Kubernetes cluster, using:

-  Citrix ingress controller

-  JetStack's [cert-manager](https://github.com/jetstack/cert-manager) to provision TLS certificates from the [Let's Encrypt project](https://letsencrypt.org/docs/).

## Prerequisites

Ensure that you have:

-  The domain for which the certificate is requested is publicly accessible.

-  Enabled RBAC on your Kubernetes cluster.

-  Deployed Citrix ADC MPX, VPX, or CPX deployed in Tier 1 or Tier 2 deployment model.

    In Tier 1 deployment model, Citrix ADC MPX or VPX is used as an Application Delivery Controller (ADC) and Citrix ingress controller running in kubernetes cluster configures the virtual services for the services running on kubernetes cluster. Citrix ADC runs the virtual service on the publicly routable IP address and offloads SSL for client traffic with the help of Let's Encrypt generated certificate.

    Similarly in Tier 2 deployment model, a TCP service is configured on the Citrix ADC (VPX/MPX) running outside the Kubernetes cluster to forward the traffic to Citrix ADC CPX instances running in Kubernetes cluster.  Citrix ADC CPX ends the SSL session and load-balances the traffic to actual service pods.

-  Deployed Citrix ingress controller. Click [here](../deployment-topologies.md#deployment-topologies.html) for various deployment scenarios.

-  Opened Port 80 for the Virtual IP address on the firewall for the Let's Encrypt CA to validate the domain for HTTP01 challenge.

-  A DNS domain that you control, where you host your web application for ACME DNS01 challenge.

-  Administrator permissions for all the deployment steps. If you encounter failures due to permissions, make sure you have administrator permission.

## Install cert-manager

Please refer [cert-manager installation documentation](https://cert-manager.io/docs/installation/kubernetes/) for installing cert-manager.

You can install the cert-manager either through using manifest files or helm chart.

Once installed, Verify in the cert-manager is up and running as explained [here](https://cert-manager.io/docs/installation/kubernetes/#verifying-the-installation)


## Deploy a sample web application

Perform the following to deploy a sample web application:

	!!! note "Note"
  [Kuard](https://github.com/kubernetes-up-and-running/kuard), a kubernetes demo application is used for reference in this topic.

1.  Create a deployment YAML file (`kuard-deployment.yaml`) for Kuard with the following configuration:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: kuard
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: kuard
    spec:
      containers:
      - image: gcr.io/kuar-demo/kuard-amd64:1
        imagePullPolicy: Always
        name: kuard
        ports:
        - containerPort: 8080
```

2.  Deploy Kuard deployment file (`kuard-deployment.yaml`) to your cluster, using the following commands:

```
% kubectl create -f kuard-deployment.yaml
deployment.extensions/kuard created
% kubectl get pod -l app=kuard
NAME                     READY   STATUS    RESTARTS   AGE
kuard-6fc4d89bfb-djljt   1/1     Running   0          24s
```

3.  Create a service for the deployment. Create a file called `service.yaml` with the following configuration:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kuard
spec:
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  selector:
    app: kuard
```

  Deploy and verify the service using the following commands:

```
 % kubectl create -f service.yaml
 service/kuard created
 % kubectl get svc kuard
 NAME    TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
 kuard   ClusterIP   10.103.49.171   <none>        80/TCP    13s
```

4.  Expose this service to outside world by creating and Ingress that is deployed on Citrix ADC CPX or VPX as Content switching virtual server.

		!!! note "Note"
    	Ensure that you change `kubernetes.io/ingress.class` to your ingress class on which Citrix ingress controller is started.

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kuard
  annotations:
    kubernetes.io/ingress.class: "citrix"
spec:
  rules:
  - host: kuard.example.com
    http:
      paths:
      - backend:
          serviceName: kuard
          servicePort: 80
```

  	!!! info "Important"
  Change the value of `spec.rules.host` to the domain that you control. Ensure that a DNS entry exists to route the traffic to Citrix ADC CPX or VPX from the internet.

   Deploy the Ingress using the following command:

```
% kubectl apply -f ingress.yml
ingress.extensions/kuard created
kubectl get ingress
NAME    HOSTS               ADDRESS   PORTS   AGE
kuard   kuard.example.com             80      7s
```

5.  Verify if the ingress is configured on Citrix ADC CPX or VPX using the following command:

```
$ kubectl exec -it cpx-ingress-5b85d7c69d-ngd72 /bin/bash
root@cpx-ingress-55c88788fd-qd4rg:/# cli_script.sh 'show cs vserver'
exec: show cs vserver
1)  k8s-192.168.8.178_80_http (192.168.8.178:80) - HTTP Type: CONTENT
	State: UP
	Last state change was at Sat Jan  4 13:36:14 2020
	Time since last state change: 0 days, 00:18:01.950
	Client Idle Timeout: 180 sec
	Down state flush: ENABLED
	Disable Primary Vserver On Down : DISABLED
	Comment: uid=MPPL57E3AFY6NMNDGDKN2VT57HEZVOV53Z7DWKH44X2SGLIH4ZWQ====
	Appflow logging: ENABLED
	Port Rewrite : DISABLED
	State Update: DISABLED
	Default:  Content Precedence: RULE
	Vserver IP and Port insertion: OFF
	L2Conn: OFF Case Sensitivity: ON
	Authentication: OFF
	401 Based Authentication: OFF
	Push: DISABLED  Push VServer:
	Push Label Rule: none
	Persistence: NONE
	Listen Policy: NONE
	IcmpResponse: PASSIVE
	RHIstate:  PASSIVE
	Traffic Domain: 0
Done

root@cpx-ingress-55c88788fd-qd4rg/# exit
exit

```

6.  Verify if the page is correctly being served when requested using the `curl` command.
```
% curl -sS -D - kuard.example.com -o /dev/null
HTTP/1.1 200 OK
Content-Length: 1458
Content-Type: text/html
Date: Thu, 21 Feb 2019 09:09:05 GMT
```

## Configure issuing ACME certificate using HTTP challenge

This section describes a way to issue ACME certificate using HTTP validation. If you want to use DNS validation, skip this section and proceed to the [next section](#issuing-an-acme-certificate-using-dns-challenge).

HTTP validation using cert-manager is simple way of getting a certificate from Let's Encrypt for your domain, wherein you prove ownership of a domain by ensuring that a particular file is present at the domain. It is assumed that you control the domain if you are able to publish the given file under a given path.

First step is to create an ACME issuer for cert-mamnager to create a client account with the ACME ceertificate authority.

For more information on ACME issuer, refer [ACME documentation](https://cert-manager.io/docs/configuration/acme/) of cert-manager.

### Deploy the Let's Encrypt cluster issuer with http01 challenge provider

The cert-manager supports two different CRDs for configuration, an `Issuer`, which is scoped to a single namespace, and a `ClusterIssuer`, which is cluster-wide.

For Citrix ingress controller to use ingress from any namespace, use `ClusterIssuer`. Alternatively you can create an `Issuer` for each namespace on which you are creating an Ingress resource.

Refer cert-manager [http validation](https://cert-manager.io/docs/tutorials/acme/http-validation/) for complete documentation.

Create an `issuer` or `ClusterIssuer` as given in

1.  Create a file called `clusterissuer-letsencrypt-staging.yaml` with the following configuration:

```yaml

apiVersion: cert-manager.io/v1alpha2
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # You must replace this email address with your own.
    # Let's Encrypt will use this to contact you about expiring
    # certificates, and issues related to your account.
    email: user@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      # Secret resource used to store the account's private key.
      name: example-issuer-account-key
    # Add a single challenge solver, HTTP01 using citrix
    solvers:
    - http01:
        ingress:
          class: citrix
```

  Spec.acme.solvers[].http01.ingress.class refers the ingress class of Citrix ingress controller. If CIC has no ingress class, you dont have to specify this field.

	!!! note "Note"
   This is an example Cluster issuer of cert-manager.io/v1alpha2 resource. Please refer [Cert-manager http01 documentation](https://cert-manager.io/docs/configuration/acme/http01/) for the latest version of the resource and configuration options.

   The staging Let's Encrypt server issues fake certificate, but it is not bound by [the API rate limits of the production server](https://letsencrypt.org/docs/rate-limits/). This approach lets you set up and test your environment without worrying about rate limits. You can repeat the same step for Let's Encrypt Production server.

   After you edit and save the file, deploy the file using the following command:
```

% kubectl apply -f issuer-letsencrypt-staging.yaml
clusterissuer "letsencrypt-staging" created
```

2.  Verify in the issuer is created and registered to the ACME server.
```
% kubectl get clusterissuer
NAME                  READY   AGE
letsencrypt-staging   True    4m46s
```

  Verify if the `ClusterIssuer` is properly registered using the command `kubectl describe issuer letsencrypt-staging`:

```
Status:
  Acme:
    Last Registered Email:  admin@example.com
    Uri:                    https://acme-staging-v02.api.letsencrypt.org/acme/acct/11986372
  Conditions:
    Last Transition Time:  2020-01-04T17:01:51Z
    Message:               The ACME account was registered with the ACME server
    Reason:                ACMEAccountRegistered
    Status:                True
    Type:                  Ready
```

### Issue certificate for ingress object

Once the issuer is successfully registered, now lets proceed to get certificate for the ingress domain 'kuard.example.com'

1. You can request certificate for a given ingress resource using the following methods:

-  Adding `Ingress-shim` annotations to the ingress object.

-  Creating a `certificate` CRD object.

 First method is quick and simple, but if you need more customization and granularity in terms of certificate renewal, you can choose the second method. Depending on your selection, skip the other method.

 **Adding `Ingress-shim` annotations to Ingress object**

 In this approach, we'll add these two annotations to ingress object for which you request certificate to be issued by the ACME server.
```
    cert-manager.io/cluster-issuer: "letsencrypt-staging"
```

!!! note "Note"
    You can find all supported annotations from cert-manager for ingress-shim, click [here](https://cert-manager.io/docs/usage/ingress/#optional-configuration).

 Modify the `ingress.yaml` to use TLS by specifying a secret.

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kuard
  annotations:
    kubernetes.io/ingress.class: "citrix"
    cert-manager.io/cluster-issuer: "letsencrypt-staging"
spec:
  tls:
  - hosts:
    - kuard.example.com
    secretName: kuard-example-tls
  rules:
  - host: kuard.example.com
    http:
      paths:
      - backend:
          serviceName: kuard
          servicePort: 80
```


 The `cert-manager.io/cluster-issuer: "letsencrypt-staging"` annotation tells cert-manager to use the `letsencrypt-staging` cluster-wide issuer that was created earlier to request a certificate from Let's Encrypt's staging servers. Cert-manager creates a `certificate` object that is used to manage the lifecycle of the certificate for `kuard.example.com`, and the value for the domain name and challenge method for the certificate object is derived from the ingress object. Cert-manager manages the contents of the secret as long as the Ingress is present in your cluster.

 Deploy the `ingress.yaml` using the following command:

```

% kubectl apply -f ingress.yml
ingress.extensions/kuard configured
% kubectl get ingress kuard
NAME    HOSTS               ADDRESS   PORTS     AGE
kuard   kuard.example.com             80, 443   4h39m
```

 **using `Certificate` CRD resource**

 Alternative to ingress shim method, you can deploy a certificate CRD object independent of ingress object. Documentation of "certificate" CRD can be found [here](https://cert-manager.io/docs/tutorials/acme/http-validation/).

 Create a file with `certificate.yaml` with the following configuration:
```yaml

apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: kuard-example-tls
  issuerRef:
    name: letsencrypt-staging
  commonName: kuard.example.com
  dnsNames:
  - www.kuard.example.com
```


 `spec.secretName` is the name of the secret where the certificate is stored on successful issuing the certificate.

 Deploy the `certificate.yaml` on the Kubernetes cluster:

```

    kubectl apply -f certificate.yaml
    certificate.cert-manager.io/example-com created
```
For HTTP challenge, cert-manager will create a temporary ingress resource to route the Let's Encrypt CA generated traffic to cert-manager challenge solver pods. On successful validations of the domain, this temporary ingress is deleted.

2. Verify that certificate custom resource is created by the cert-manager which represents the certificate specified in the ingress. After few minutes, if ACME validation goes well, certificate 'READY' status will be set to true.
```

  % kubectl get certificates.cert-manager.io kuard-example-tls
  NAME                READY   SECRET              AGE
  kuard-example-tls   True    kuard-example-tls   3m44s


  % kubectl get certificates.cert-manager.io kuard-example-tls
   Name:         kuard-example-tls
   Namespace:    default
   Labels:       <none>
   Annotations:  <none>
   API Version:  cert-manager.io/v1alpha2
   Kind:         Certificate
   Metadata:
     Creation Timestamp:  2020-01-04T17:36:26Z
     Generation:          1
     Owner References:
       API Version:           extensions/v1beta1
       Block Owner Deletion:  true
       Controller:            true
       Kind:                  Ingress
       Name:                  kuard
       UID:                   2cafa1b4-2ef7-11ea-8ba9-06bea3f4b04a
     Resource Version:        81263
     Self Link:               /apis/cert-manager.io/v1alpha2/namespaces/default/certificates/kuard-example-tls
     UID:                     bbfa5e51-2f18-11ea-8ba9-06bea3f4b04a
   Spec:
     Dns Names:
       acme.cloudpst.net
     Issuer Ref:
       Group:      cert-manager.io
       Kind:       ClusterIssuer
       Name:       letsencrypt-staging
     Secret Name:  kuard-example-tls
   Status:
     Conditions:
       Last Transition Time:  2020-01-04T17:36:28Z
       Message:               Certificate is up to date and has not expired
       Reason:                Ready
       Status:                True
       Type:                  Ready
     Not After:               2020-04-03T16:36:27Z
   Events:
     Type    Reason        Age   From          Message
     ----    ------        ----  ----          -------
     Normal  GeneratedKey  24m   cert-manager  Generated a new private key
     Normal  Requested     24m   cert-manager  Created new CertificateRequest resource "kuard-example-tls-3030465986"
     Normal  Issued        24m   cert-manager  Certificate issued successfully
```

3. Verify that secret resource is created

```
 kubectl get secret  kuard-example-tls
 NAME                TYPE                DATA   AGE
 kuard-example-tls   kubernetes.io/tls   3      3m13s
```


## Issuing an ACME certificate using DNS challenge

This section describes a way to use DNS validation to get ACME certificate from Let'sEncrypt CA. With a DNS-01 challenge, you prove the ownership of a domain by proving you control its DNS records. This is done by creating a TXT record with specific content that proves you have control of the domain's DNS records. For detailed explanation of DNS challenge and best security practices in deploying DNS challenge, see [A Technical Deep Dive: Securing the Automation of ACME DNS Challenge Validation](https://www.eff.org/deeplinks/2018/02/technical-deep-dive-securing-automation-acme-dns-challenge-validation).

!!!	note "Note"
		This tutorial assumes `route53` DNS provider. For other providers, please refer cert-manager [documentation of  DNS validaiton](https://cert-manager.io/docs/configuration/acme/dns01/)

### Deploy the Let's Encrypt cluster issuer with dns01 challenge provider

1. Create AWS IAM user account and download the Secret Access Key ID and Secret Access Key

2. Grant following IAM policy to your user:
  - [Route53 access policy](http://docs.cert-manager.io/en/latest/tasks/issuers/setup-acme/dns01/route53.html)

3. Create a Kubernetes secret `acme-route53` in `kube-system` namespace
```
kubectl create secret generic acme-route53 --from-literal secret-access-key=<secret_access_key>
```

4.  Create an `Issuer` or `ClusterIssuer` with dns01 challenge provider.

    You can provide multiple dns01 solvers in the cluster issuer, and specify which provider to be used at the time of certificate creation.
    You need to have access to the DNS provider for cert-manager to create a TXT record, the credentials are stored in Kubernetes secret specified in `spec.dns01.secretAccessKeySecretRef`.

```
apiVersion: cert-manager.io/v1alpha2
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # You must replace this email address with your own.
    # Let's Encrypt will use this to contact you about expiring
    # certificates, and issues related to your account.
    email: user@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: example-issuer-account-key
    solvers:
    - dns01:
        route53:
          region: us-west-2
          accessKeyID: AKIA55XBQO7EXMOEF66E
          secretAccessKeySecretRef:
            name: acme-route53
            key: secret-access-key
```


  	!!! note "Note"
    Replace `user@example.com` with your email address.

   For each domain mentioned in a dns01 stanza, cert-manager will use the provider's credentials from the referenced Issuer to create a TXT record called `_acme-challenge`. This record is then verified by the ACME server in order to issue the certificate. For more information about the DNS provider configuration, and the list of supported providers, see [dns01 reference doc](https://cert-manager.io/docs/configuration/acme/dns01/).

   After you edit and save the file, deploy the file using the following command:
```
% kubectl apply -f acme_clusterissuer_dns.yaml
clusterissuer.cert-manager.io/letsencrypt-staging created
```

  5. Verify if the issuer is created and registered to the ACME server using the following command:
```

kubectl get clusterissuer
NAME                  READY   AGE
letsencrypt-staging   True    4s
```

  Verify if the `ClusterIssuer` is properly registered using the command `kubectl describe issuer letsencrypt-staging`:

```
Status:
  Acme:
    Last Registered Email:  user@example.com
    Uri:                    https://acme-staging-v02.api.letsencrypt.org/acme/acct/11986372
  Conditions:
    Last Transition Time:  2020-01-05T07:42:46Z
    Message:               The ACME account was registered with the ACME server
    Reason:                ACMEAccountRegistered
    Status:                True
    Type:                  Ready
```

### Issue certificate for ingress object

1. Once the issuer is successfully registered, lets proceed to get certificate for the ingress domain `kuard.example.com`. Similar to http01 challenge, there are two ways you can request the certificate for a given ingress resource:

-  Adding `Ingress-shim` annotations to the ingress object.

-  Creating a `certificate` CRD object.

**Adding `Ingress-shim` annotations to the ingress object**

Add the following annotations to the ingress object along with `spec.tls` section:

```YAML
cert-manager.io/cluster-issuer: "letsencrypt-staging"
```


```YAML
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kuard
  annotations:
    kubernetes.io/ingress.class: "citrix"
    cert-manager.io/cluster-issuer: "letsencrypt-staging"
spec:
  tls:
  - hosts:
    - kuard.example.com
    secretName: kuard-example-tls
  rules:
  - host: kuard.example.com
    http:
      paths:
      - backend:
          serviceName: kuard
          servicePort: 80
```

The cert-manager creates a `Certificate` CRD resource with dns01 challenge and it uses the credentials given in the `ClusterIssuer` to create a TXT record in the DNS server for the domain you own. Then, Let's Encypt CA validates the content of the TXT record to complete the challenge.

**Adding `Certificate` CRD resource**

Alternative to `ingress-shim` approach, you can explicitly create a certificate custom resource definition resource to trigger automatic generation of certificates.

Create a file with `certificate.yaml` with the following configuration:
```yaml

apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: kuard-example-tls
  issuerRef:
    name: letsencrypt-staging
  commonName: kuard.example.com
  dnsNames:
  - www.kuard.example.com
```
After succesful validation of the domain name, certificate READY status is set to True.

2. Verify if the certificate is issued

```
kubectl get certificate kuard-example-tls
NAME                READY   SECRET              AGE
kuard-example-tls   True    kuard-example-tls   10m
```


You can watch the progress of the certificate as it's issued, use the following command:

```
kubectl describe certificates kuard-example-tls  | tail -n 6
  Not After:               2020-04-04T13:34:23Z
Events:
  Type    Reason     Age    From          Message
  ----    ------     ----   ----          -------
  Normal  Requested  11m    cert-manager  Created new CertificateRequest resource "kuard-example-tls-3030465986"
  Normal  Issued     7m21s  cert-manager  Certificate issued successfully
```

## Verify the certificate in citrix ADC

Letsencrypt CA successfully validated the domain and issued a new certificate for the domain. A `kubernetes.io/tls` secret is created with the `secretName` specified in the `tls:` field of the Ingress. Also, cert-manager automatically initiates a renewal, 30 days before the expiry.

Verify in the secret is created using the following command:
```

% kubectl get secret kuard-example-tls
NAME                TYPE                DATA   AGE
kuard-example-tls   kubernetes.io/tls   3      30m
```

The secret is picked up by Citrix ingress controller and binds the certificate to the Content switching virtual server on the Citrix ADC CPX.
If there are any intermediate CA certificate, it is automatically linked to the server certificate and presented to the client during SSL negotiation.

Log on to Citrix ADC CPX and verify if the certificate is bound to the SSL virtual server.
```
% kubectl exec -it cpx-ingress-55c88788fd-n2x9r bash -c cpx-ingress
Defaulting container name to cpx-ingress.
Use 'kubectl describe pod/cpx-ingress-55c88788fd-n2x9r -n default' to see all of the containers in this pod.

% cli_script.sh 'sh ssl vs k8s-192.168.8.178_443_ssl'
exec: sh ssl vs k8s-192.168.8.178_443_ssl

	Advanced SSL configuration for VServer k8s-192.168.8.178_443_ssl:
	DH: DISABLED
	DH Private-Key Exponent Size Limit: DISABLED	Ephemeral RSA: ENABLED		Refresh Count: 0
	Session Reuse: ENABLED		Timeout: 120 seconds
	Cipher Redirect: DISABLED
	ClearText Port: 0
	Client Auth: DISABLED
	SSL Redirect: DISABLED
	Non FIPS Ciphers: DISABLED
	SNI: ENABLED
	OCSP Stapling: DISABLED
	HSTS: DISABLED
	HSTS IncludeSubDomains: NO
	HSTS Max-Age: 0
	HSTS Preload: NO
	SSLv3: ENABLED  TLSv1.0: ENABLED  TLSv1.1: ENABLED  TLSv1.2: ENABLED  TLSv1.3: DISABLED
	Push Encryption Trigger: Always
	Send Close-Notify: YES
	Strict Sig-Digest Check: DISABLED
	Zero RTT Early Data: DISABLED
	DHE Key Exchange With PSK: NO
	Tickets Per Authentication Context: 1
, P_256, P_384, P_224, P_5216)	CertKey Name: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS	Server Certificate for SNI

7)	Cipher Name: DEFAULT
	Description: Default cipher list with encryption strength >= 128bit
Done

% cli_script.sh 'sh certkey'
1)	Name: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS
	Cert Path: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS.crt
	Key Path: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS.key
	Format: PEM
	Status: Valid,   Days to expiration:89
	Certificate Expiry Monitor: ENABLED
	Expiry Notification period: 30 days
	Certificate Type:	"Client Certificate"	"Server Certificate"
	Version: 3
	Serial Number: 03B2B57EA9E61A93F1D05EA3272FA95203C2
	Signature Algorithm: sha256WithRSAEncryption
	Issuer:  C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
	Validity
		Not Before: Jan  5 13:34:23 2020 GMT
		Not After : Apr  4 13:34:23 2020 GMT
	Subject:  CN=acme.cloudpst.net
	Public Key Algorithm: rsaEncryption
	Public Key size: 2048
	Ocsp Response Status: NONE
2)	Name: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS_ic1
	Cert Path: k8s-GVWNYGVZKKRHKF7MZVTLOAEZYBS.crt_ic1
	Format: PEM
	Status: Valid,   Days to expiration:437
	Certificate Expiry Monitor: ENABLED
	Expiry Notification period: 30 days
	Certificate Type:	"Intermediate CA"
	Version: 3
	Serial Number: 0A0141420000015385736A0B85ECA708
	Signature Algorithm: sha256WithRSAEncryption
	Issuer:  O=Digital Signature Trust Co.,CN=DST Root CA X3
	Validity
		Not Before: Mar 17 16:40:46 2016 GMT
		Not After : Mar 17 16:40:46 2021 GMT
	Subject:  C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
	Public Key Algorithm: rsaEncryption
	Public Key size: 2048
	Ocsp Response Status: NONE
Done
```

The HTTPS webserver is now UP with fake LE signed certificate. Next step is to move to production with actual Let's Encrypt certificate.

## Move to production

After successfully testing with Let's Encrypt-staging, you can get the actual Let's Encrypt certificates.

You need to change Let's Encrypt endpoint from `https://acme-staging-v02.api.letsencrypt.org/directory` to `https://acme-v02.api.letsencrypt.org/directory`

Then, change the name of the ClusterIssuer from `letsencrypt-staging` to `letsencrypt-production`


```yaml

apiVersion: cert-manager.io/v1alpha2
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # You must replace this email address with your own.
    # Let's Encrypt will use this to contact you about expiring
    # certificates, and issues related to your account.
    email: user@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      # Secret resource used to store the account's private key.
      name: example-issuer-account-key
    # Add a single challenge solver, HTTP01 using citrix
    solvers:
    - http01:
        ingress:
          class: citrix
```


	!!! note "Note"
   Replace `user@example.com` with your email address.

Deploy the file using the following command:
```
% kubectl apply -f letsencrypt-prod.yaml
  clusterissuer "letsencrypt-prod" created
```

Now repeat the procedure of modifying the annotation in ingress or creating a new CRD certificate which will trigger the generation of new certificate.

	!!! note "Note"
  Ensure that you delete the old secret so that cert-manager starts a fresh challenge with the production CA.

```
 % kubectl delete secret kuard-example-tls
 secret "kuard-example-tls" deleted
```

Once the HTTP website is up, you can redirect the traffic from HTTP to HTTPS using the annotation `ingress.citrix.com/insecure-termination: redirect` in the ingress object.

## Troubleshooting

Since the certificate generation involves multiple components, this section summarizes the troubleshooting techniques that you can use in case of failures.

### Verify the current status of certificate generation

Certificate CRD object defines the life cycle management of generation and renewal of the certificates. You can view the status of the certificate using `kubectl describe` command as shown below.

```

    % kubectl get certificate
    NAME                READY   SECRET              AGE
    kuard-example-tls   False   kuard-example-tls   9s

    %  kubectl describe certificate kuard-example-tls

    Status:
      Conditions:
        Last Transition Time:  2019-03-05T09:50:29Z
        Message:               Certificate does not exist
        Reason:                NotFound
        Status:                False
        Type:                  Ready
    Events:
      Type    Reason        Age   From          Message
      ----    ------        ----  ----          -------
      Normal  OrderCreated  22s   cert-manager  Created Order resource "kuard-example-tls-1754626579"
```

Also you can view the major certificate events using the `kubectl events` commands:

```
    kubectl get events
    LAST SEEN   TYPE     REASON              KIND          MESSAGE
    36s         Normal   Started             Challenge     Challenge scheduled for processing
    36s         Normal   Created             Order         Created Challenge resource "kuard-example-tls-1754626579-0" for domain "acme.cloudpst.net"
    38s         Normal   OrderCreated        Certificate   Created Order resource "kuard-example-tls-1754626579"
    38s         Normal   CreateCertificate   Ingress       Successfully created Certificate "kuard-example-tls"
```

### Analyze the logs from cert-manager

In case of failure, first step is to analyze the logs from the cert-manager component.  Identify the cert-manager pod using the following command:
```

    kubectl get po -n cert-manager
    NAME                                    READY   STATUS      RESTARTS   AGE
    cert-manager-76d48d47bf-5w4vx           1/1     Running     0          23h
    cert-manager-webhook-67cfb86d56-6qtxr   1/1     Running     0          23h
    cert-manager-webhook-ca-sync-x4q6f      0/1     Completed   4          23h
```

Here `cert-manager-76d48d47bf-5w4vx` is the main cert-manager pod, and other two pods are cert-manager webhook pods.

Get the logs of the cert-manager using the following command:
```

    kubectl logs -f cert-manager-76d48d47bf-5w4vx -n cert-manager
```

If there is any failure to get the certificate, the ERROR logs give details about the failure.

### Check the Kubernetes secret

Use `kubectl describe` command to verify if both certificates and key are populated in Kubernetes secret.
```

 % kubectl describe secret kuard-example-tls
 Name:         kuard-example-tls
 Namespace:    default
 Labels:       certmanager.k8s.io/certificate-name=kuard-example-tls
 Annotations:  certmanager.k8s.io/alt-names: acme.cloudpst.net
							 certmanager.k8s.io/common-name: acme.cloudpst.net
							 certmanager.k8s.io/issuer-kind: ClusterIssuer
							 certmanager.k8s.io/issuer-name: letsencrypt-staging

 Type:  kubernetes.io/tls

 Data
 ====
 tls.crt:  3553 bytes
 tls.key:  1679 bytes
 ca.crt:   0 bytes

```

If both `tls.crt` and `tls.key` are populated in the kubernetes secret, certificate generation is complete.  If only tls.key is present, certificate generation is incomplete. Analyze the cert-manager logs for more details about the issue.

### Analyze the logs from Citrix ingress controller

If kubernetes secret is generated and complete, but this secret is not uploaded to Citrix ADC CPX or VPX, you can analyze the logs from Citrix ingress controller using `kubectl logs` command.

```

% kubectl logs -f cpx-ingress-685c8bc976-zgz8q -c cic
```