var socket;
var flagFistTime = 1;
var flagTimeOut = 0;
var wsTimeout;
var mapRequestID = new Map();

class ISPluginClient {
  constructor(
    ip,
    port,
    isSecure,
    cbReceivedDocument,
    cbReceivedBiometricAuth,
    cbReceivedCardDetecionEvent,
    cbConnected,
    cbDisconnected = function () {},
    cbStopped,
    cbConnectionDenied,
    cbReceive
  ) {
    //lam----
    flagTimeOut = 0;
    var url = isSecure + "://" + ip + ":" + port + "/ISPlugin";
    socket = new WebSocket(url);

    function shutdown() {
      flagTimeOut = 1;
      socket.close(1000, "work complete");
    }

    socket.onopen = function (event) {
      console.log("socket open");
      clearTimeout(wsTimeout);
      flagFistTime = 1;
      cbConnected();
    };

    socket.onclose = function (event) {
      console.log(`Closed ${event.code}`);

      if (flagTimeOut === 0) {
        console.log("reconnect!!!");
        if (flagFistTime === 1) {
          flagFistTime = 0;
          cbDisconnected();
          wsTimeout = setTimeout(timeoutWS, 30000);
          function timeoutWS() {
            if (socket.readyState !== 1) {
              flagTimeOut = 1;
              console.log("connect failure!");
              clearTimeout(wsTimeout);
              flagFistTime = 1;
              cbStopped();
              socket.close(1000, "Connect failure");
            }
          }
        }

        new ISPluginClient(
          ip,
          port,
          isSecure,
          cbReceivedDocument,
          cbReceivedBiometricAuth,
          cbReceivedCardDetecionEvent,
          cbConnected,
          cbDisconnected,
          cbStopped,
          cbConnectionDenied,
          cbReceive
        );
      }
    };

    socket.onmessage = function (event) {
      console.log("onmessage");
      var response = {};
      response = JSON.parse(event.data);
      console.log(event);
      console.log("response", response);

      if (!response) {
        console.log("Skip Response because response is null");
      } else {
        var cmd = response.cmdType;
        var id = response.requestID;
        var error = response.errorCode;
        var errorMsg = response.errorMessage;
        var data = response.data;

        if (!cmd) {
          console.log("Skip Response because cmdType is null");
          if (error && error === 1008) {
            cbConnectionDenied(errorMsg);
          }
        } else {
          if (cbReceive) {
            cbReceive(cmd, id, error, data);
          }
          if (cmd === "SendInfoDetails") {
            cbReceivedDocument(response);
          } else if (cmd === "CardDetectionEvent") {
            cbReceivedCardDetecionEvent(response);
          } else if (cmd === "SendBiometricAuthentication") {
            cbReceivedBiometricAuth(response);
          } else if (mapRequestID.has(id)) {
            var req = mapRequestID.get(id);
            mapRequestID.delete(id);
            console.log("dzo dau na");
            if (!req) {
            } else if (req.cmdType !== cmd) {
              //error if != cmdType
              req.cb_error(
                -1,
                "cmdType does not match, got [" +
                  cmd +
                  "] but expect [" +
                  req.cmdType +
                  "]"
              );
            } else if (error === 0) {
              //success
              if (req.cmdType === "BiometricAuthentication") {
                console.log("dzo BiometricAuthentication");
                req.cb_success(response);
              } else {
                console.log("dzo dong 114");
                req.cb_success(data);
              }
            } else {
              //error
              req.cb_error(error, errorMsg);
            }
          } else {
            console.log(
              "Skip Response because not found requestID [" + id + "]"
            );
          }
        }
      }
    };

    function create_uuidv4() {
      return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c) =>
        (
          c ^
          (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))
        ).toString(16)
      );
    }

    function getDeviceDetails(
      deviceDetailsEnabled,
      presenceEnabled,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "GetDeviceDetails",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "GetDeviceDetails",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            deviceDetailsEnabled: deviceDetailsEnabled,
            presenceEnabled: presenceEnabled,
          },
        })
      );

      let getDeviceDetailsTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout(); //callback when time out
        }
      }, timeOutInterval * 1000);
    }

    // = getInformationDetails old
    function getDocumentDetails(
      mrzEnabled,
      imageEnabled,
      dataGroupEnabled,
      optionalDetailsEnabled,
      canValue,
      challenge,
      caEnabled,
      taEnabled,
      paEnabled,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "GetInfoDetails",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "GetInfoDetails",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            mrzEnabled: mrzEnabled,
            imageEnabled: imageEnabled,
            dataGroupEnabled: dataGroupEnabled,
            optionalDetailsEnabled: optionalDetailsEnabled,
            canValue: canValue,
            challenge: challenge,
            caEnabled: caEnabled,
            taEnabled: taEnabled,
            paEnabled: paEnabled,
          },
        })
      );

      let getDocumentDetailsTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function biometricAuthentication(
      biometricType,
      challengeBiometric,
      challengeType,
      livenessEnabled,
      cardNo,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      console.log("bat dau biometricAuthentication");
      mapRequestID.set(requestID, {
        cmdType: "BiometricAuthentication",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "BiometricAuthentication",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            biometricType: biometricType,
            cardNo: cardNo,
            livenessEnabled: livenessEnabled,
            challengeType: challengeType,
            challenge: challengeBiometric,
          },
        })
      );

      let biometricAuthenticationTimeOut = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
      console.log("biometricAuthentication ket thuc");
    }

    function connectToDevice(
      confirmEnabled,
      confirmCode,
      clientName,
      automaticEnabled,
      mrzEnabled,
      imageEnabled,
      dataGroupEnabled,
      optionalDetailsEnabled,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "ConnectToDevice",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "ConnectToDevice",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            clientName: clientName,
            confirmEnabled: confirmEnabled,
            confirmCode: confirmCode,
            configuration: {
              automaticEnabled: automaticEnabled,
              mrzEnabled: mrzEnabled,
              imageEnabled: imageEnabled,
              dataGroupEnabled: dataGroupEnabled,
              optionalDetailsEnabled: optionalDetailsEnabled,
            },
          },
        })
      );

      let connectToDeviceTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function displayInformation(
      title,
      type,
      value,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "DisplayInformation",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "DisplayInformation",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            title: title,
            type: type,
            value: value,
          },
        })
      );
      let displayInformationTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function refreshReader(
      deviceDetailsEnabled,
      presenceEnabled,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "Refresh",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "Refresh",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            deviceDetailsEnabled: deviceDetailsEnabled,
            presenceEnabled: presenceEnabled,
          },
        })
      );

      let refreshReaderTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function scanDocument(
      scanType,
      saveEnabled,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "ScanDocument",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "ScanDocument",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            scanType: scanType,
            saveEnabled: saveEnabled,
          },
        })
      );

      let scanDocumentTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function getBiometricEvidence(
      biometricType,
      timeOutInterval,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "BiometricEvidence",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      socket.send(
        JSON.stringify({
          cmdType: "BiometricEvidence",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          data: {
            biometricType: biometricType,
          },
        })
      );

      let biometricEvidenceTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function getTokenCertificate(
      timeOutInterval,
      dllNameList,
      currentDomain,
      lang,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "GetTokenCertificates",
        cb_success: cbSuccess,
        cb_error: cbError,
      });

      socket.send(
        JSON.stringify({
          cmdType: "GetTokenCertificates",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          lang,
          data: {
            // dllNames: ["cmcca_csp11_v1", "eps2003csp11"],
            dllNames: dllNameList,
            currentDomain,
          },
        })
      );

      let getTokenCertificateTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    function signTokenCertificate(
      certId,
      certPin,
      signObjects,
      timeOutInterval,
      lang,
      cbSuccess,
      cbError,
      cbTimeout
    ) {
      var requestID = create_uuidv4();
      mapRequestID.set(requestID, {
        cmdType: "SignTokenCertificate",
        cb_success: cbSuccess,
        cb_error: cbError,
      });
      connectorLogRequest.pURL = "SignTokenCertificate";
      connectorLogRequest.pREQUEST = JSON.stringify({
        cmdType: "SignTokenCertificate",
        requestID: requestID,
        timeOutInterval: timeOutInterval,
        lang,
        data: {
          certId,
          certPin,
          currentDomain: "id.mobile-id.vn",
          signObjects,
        },
      });
      socket.send(
        JSON.stringify({
          cmdType: "SignTokenCertificate",
          requestID: requestID,
          timeOutInterval: timeOutInterval,
          lang,
          data: {
            certId,
            certPin,
            currentDomain: "id.mobile-id.vn",
            signObjects,
          },
        })
      );
      let signTokenCertificateTimeout = setTimeout(function () {
        if (mapRequestID.has(requestID)) {
          mapRequestID.delete(requestID);
          cbTimeout();
        }
      }, timeOutInterval * 1000);
    }

    return {
      getDeviceDetails: getDeviceDetails,
      getDocumentDetails: getDocumentDetails,
      biometricAuthentication: biometricAuthentication,
      connectToDevice: connectToDevice,
      displayInformation: displayInformation,
      refreshReader: refreshReader,
      scanDocument: scanDocument,
      getBiometricEvidence: getBiometricEvidence,
      getTokenCertificate: getTokenCertificate,
      signTokenCertificate: signTokenCertificate,
      shutdown: shutdown,
    };
  }
}

class OCRClient {
  constructor(apikey = "", access_key = "", secret_key = "", basic_key = "", service = "", region = "", host = "") {

    // utils
    async function sha256(string) {
      const utf8 = new TextEncoder().encode(string);
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", utf8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray
        .map((bytes) => bytes.toString(16).padStart(2, "0"))
        .join("");
      return hashHex;
    }

    function handleFixBase64(base64) {
      // remove data:image/ if exist
      if (base64.indexOf("data:image/") !== -1) {
        base64 = base64.split(",")[1];
      }
      return base64;
    }

    function sign(key, msg) {
      return CryptoJS.HmacSHA256(msg, key);
    }

    function getSignatureKey(key, dateStamp, regionName, serviceName) {
      var kDate = sign("AWS4" + key, dateStamp);
      var kRegion = sign(kDate, regionName);
      var kService = sign(kRegion, serviceName);
      var kSigning = sign(kService, "aws4_request");
      return kSigning;
    }

    function strftime(format, date) {
      const pad = (number) => (number < 10 ? "0" : "") + number;

      const tokens = {
        "%Y": date.getUTCFullYear(),
        "%m": pad(date.getUTCMonth() + 1),
        "%d": pad(date.getUTCDate()),
        "%H": pad(date.getUTCHours()),
        "%M": pad(date.getUTCMinutes()),
        "%S": pad(date.getUTCSeconds()),
      };

      let result = format;
      for (const token in tokens) {
        result = result.replace(token, tokens[token]);
      }

      return result;
    }

    // main
    function getToken() {
      return new Promise(async (resolve, reject) => {
        try {
          const request_parameters = "";
          const method = "GET";
          const path = "/dtis/v2/e-identity/general/token/get";
          const date = new Date();
          const amzdate = strftime("%Y%m%dT%H%M%SZ", date);
          const datestamp = strftime("%Y%m%d", date);
          const securityToken = `Basic ${basic_key}`;

          // ************* TASK 1: CREATE A CANONICAL REQUEST *************
          const canonical_uri = path;
          const canonical_querystring = request_parameters;
          const canonical_headers =
            "host:" +
            host +
            "\n" +
            "x-amz-date:" +
            amzdate +
            "\n" +
            "x-amz-security-token:" +
            securityToken +
            "\n" +
            "x-api-key:" +
            apikey;

          const signed_headers =
            "host;x-amz-date;x-amz-security-token;x-api-key";

          const payload_hash = await sha256(request_parameters);
          const canonical_request =
            method +
            "\n" +
            canonical_uri +
            "\n" +
            canonical_querystring +
            "\n" +
            canonical_headers +
            "\n\n" +
            signed_headers +
            "\n" +
            payload_hash;

          // ************* TASK 2: CREATE THE STRING TO SIGN*************
          var algorithm = "AWS4-HMAC-SHA256";
          var credential_scope =
            datestamp + "/" + region + "/" + service + "/" + "aws4_request";
          var data = await sha256(canonical_request);

          var string_to_sign =
            algorithm +
            "\n" +
            amzdate +
            "\n" +
            credential_scope +
            "\n" +
            data.toString();

          // ************* TASK 3: CALCULATE THE SIGNATURE *************
          var signing_key = getSignatureKey(
            secret_key,
            datestamp,
            region,
            service
          );
          var signature = sign(signing_key, string_to_sign);

          // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
          var authorization_header =
            algorithm +
            " " +
            "Credential=" +
            access_key +
            "/" +
            credential_scope +
            ", " +
            "SignedHeaders=" +
            signed_headers +
            ", " +
            "Signature=" +
            signature;
          const headers = new Headers();
          headers.append("x-amz-date", amzdate);
          headers.append("Authorization", authorization_header);
          headers.append("host", host);
          headers.append("x-amz-security-token", securityToken);
          headers.append("x-api-key", apikey);

          const options = {
            method: method, // specify the HTTP method (GET, POST, etc.)
            headers: headers,
          };

          fetch("https://" + host + path, options)
            .then((response) => {
              return response.json();
            })
            .then((data) => {
              resolve(data.access_token);
            })
            .catch((err) => {
              reject(err);
            });
        } catch (error) {
          reject(error);
        }
      });
    }

    function getOCR(accessToken, documentType, cameraDeviceId) {
      return new Promise((resolve, reject) => {
        try {
          const clientHeight = window.innerHeight;
          const clientWidth = window.innerWidth;
          const securityToken = `Bearer ${accessToken}`;
          var webcamWindow = window.open(
            "",
            "WebcamWindow",
            `width=${clientWidth},height=${clientHeight},top=0,left=0`
          );

          // fetch("/video.html").then(function (response) {
          // response.text().then(function (text) {
          webcamWindow.document.write(`<html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <script src="https://cdn.tailwindcss.com"></script>
                <title>Document</title>
              </head>
              <body>
                <div class="flex">
                  <div class="relative mx-auto mt-10">
                    <video id="video" autoplay></video>
                    <div
                      class="absolute top-0 left-0 bg-black bg-opacity-60 z-10 w-full h-[25%]"
                    ></div>
                    <div
                      class="absolute bottom-0 left-0 bg-black bg-opacity-60 z-10 w-full h-[25%]"
                    ></div>
                    <div
                      class="absolute top-1/2 -translate-y-1/2 left-0 bg-black bg-opacity-60 z-10 w-[20%] h-[50%]"
                    ></div>
                    <div
                      class="absolute top-1/2 -translate-y-1/2 right-0 bg-black bg-opacity-60 z-10 w-[20%] h-[50%]"
                    ></div>
                  </div>
                </div>
                <div class="flex items-center justify-center">
                  <button
                    id="snap"
                    class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Snap
                  </button>
                </div>
                <div class="flex items-center justify-around text-center">
                  <div>
                    <span>Mặt trước</span>
                    <img id="img-document-front"></img>
                  </div>
                  <div>
                    <span>Mặt sau</span>
                    <img id="img-document-back"></img>
                  </div>
                </div>
              </body>
              <script>
                const video = document.getElementById("video");
                const imgDocumentFront = document.getElementById("img-document-front");
                const imgDocumentBack = document.getElementById("img-document-back");
                const snap = document.getElementById("snap");
                const close = document.getElementById("close");
            
                navigator.mediaDevices
                ${
                  cameraDeviceId
                    ? `.getUserMedia({ video: { deviceId: "${cameraDeviceId}" } })`
                    : ".getUserMedia({ video: true })"
                }
                  .then((stream) => {
                    const width = stream.getVideoTracks()[0].getSettings().width;
                    const height = stream.getVideoTracks()[0].getSettings().height;
                    video.srcObject = stream;
                    video.style.width = width;
                    video.style.height = height;
                    snap.addEventListener("click", () => {
                      const canvas = document.createElement("canvas");
                      const ctx = canvas.getContext("2d");
                      canvas.width = width;
                      canvas.height = height;
                      ctx.drawImage(
                        video,
                        (width * 20) / 100,
                        (height * 25) / 100,
                        (width * 60) / 100,
                        (height * 50) / 100,
                        0,
                        0,
                        width,
                        height
                      );
                      const data = canvas.toDataURL("image/png");
                      if (imgDocumentFront.src === "") {
                        imgDocumentFront.src = data;
                        imgDocumentFront.style.width = width * 0.6;
                        imgDocumentFront.style.height = height * 0.5;
                        window.data = {
                          ...window.data,
                          front: data,
                        };
                      } else {
                        imgDocumentBack.src = data;
                        imgDocumentBack.style.width = width * 0.6;
                        imgDocumentBack.style.height = height * 0.5;
                        window.data = {
                          ...window.data,
                          back: data,
                        };
                        window.close();
                      };
                    });
                  })
                  .catch((error) => {
                    console.error("Error accessing webcam:", error);
                  });
              </script>
            </html>
            `);
          const timer = setInterval(async () => {
            try {
              if (webcamWindow.closed) {
                clearInterval(timer);
                let webcamWindowData = webcamWindow.data || {};
                const { front, back } = webcamWindowData;
                webcamWindowData = null;
                if (!front || !back) {
                  reject({
                    message: "Not enough image to process",
                    data: {
                      front,
                      back,
                    },
                  });
                }
                // start request
                var method = "POST";
                var path = "/dtis/v2/e-identity/utility/ocr/document/get";

                var date = new Date();
                var amzdate = strftime("%Y%m%dT%H%M%SZ", date);
                var datestamp = strftime("%Y%m%d", date);

                var canonical_uri = path;
                var canonical_querystring = "";
                var canonical_headers =
                  "host:" +
                  host +
                  "\n" +
                  "x-amz-date:" +
                  amzdate +
                  "\n" +
                  "x-amz-security-token:" +
                  securityToken +
                  "\n" +
                  "x-api-key:" +
                  apikey;

                var signed_headers =
                  "host;x-amz-date;x-amz-security-token;x-api-key";

                const request_parameters = JSON.stringify({
                  document_front: handleFixBase64(front),
                  document_back: handleFixBase64(back),
                  document_type: documentType,
                });

                console.log(request_parameters);

                var payload_hash = await sha256(request_parameters);
                var canonical_request =
                  method +
                  "\n" +
                  canonical_uri +
                  "\n" +
                  canonical_querystring +
                  "\n" +
                  canonical_headers +
                  "\n\n" +
                  signed_headers +
                  "\n" +
                  payload_hash;

                var algorithm = "AWS4-HMAC-SHA256";
                var credential_scope =
                  datestamp +
                  "/" +
                  region +
                  "/" +
                  service +
                  "/" +
                  "aws4_request";
                var hashCanonicalRequest = await sha256(canonical_request);

                var string_to_sign =
                  algorithm +
                  "\n" +
                  amzdate +
                  "\n" +
                  credential_scope +
                  "\n" +
                  hashCanonicalRequest.toString();

                var signing_key = getSignatureKey(
                  secret_key,
                  datestamp,
                  region,
                  service
                );
                var signature = sign(signing_key, string_to_sign);

                var authorization_header =
                  algorithm +
                  " " +
                  "Credential=" +
                  access_key +
                  "/" +
                  credential_scope +
                  ", " +
                  "SignedHeaders=" +
                  signed_headers +
                  ", " +
                  "Signature=" +
                  signature;
                var headers = {
                  "x-amz-date": amzdate,
                  Authorization: authorization_header,
                  host: host,
                  "x-amz-security-token": securityToken,
                  "x-api-key": apikey,
                };

                fetch("https://" + host + path, {
                  host: host,
                  port: 443,
                  method: method,
                  path: path,
                  headers: headers,
                  body: request_parameters,
                })
                  .then((response) => {
                    return response.json();
                  })
                  .then((data) => {
                    resolve(data);
                  })
                  .catch((err) => {
                    reject(err);
                  });
              }
            } catch (err) {
              throw err;
            }
          }, 500);
          // });
          // });
        } catch (err) {
          reject(err);
        }
      });
    }

    function facialProcess(
      accessToken = "",
      process_type,
      originalFrame = "",
      cameraDeviceId,
      osType = "WIN",
      lang = "EN"
    ) {
      return new Promise((resolve, reject) => {
        const securityToken = `Bearer ${accessToken}`;
        const clientHeight = window.innerHeight;
        const clientWidth = window.innerWidth;
        var liveNessWebcamWindow = window.open(
          "",
          "liveNessWebcamWindow",
          `width=${clientWidth},height=${clientHeight},top=0,left=0`
        );

        // fetch("/liveness.html").then(function (response) {
        // response.text().then(function (text) {
        liveNessWebcamWindow.document.write(`<!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Document</title>
              </head>
              <body>
                <div class="flex items-center justify-center h-screen w-full">
                 <div>
                  <div id="video-container" class="relative">
                    <video id="video" autoplay></video>
                    <canvas id="canvas" class="absolute z-10 top-0 left-0"></canvas>
                    <div
                      class="absolute top-0 left-0 w-full h-full z-20 flex items-center justify-center"
                    >
                      <div>
                        <span id="nose-point" class="relative flex h-3 w-3 mx-auto">
                          <span
                            class="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75"
                          ></span>
                        </span>
                      </div>
                    </div>
                  </div>
                  <div class="text-center">Vui lòng đưa khuôn mặt của bạn vào đúng vị trí trung tâm của màn hình</div>
                 </div>
                </div>
              </body>
              <script src="https://cdn.tailwindcss.com"></script>
              <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs"></script>
              <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/blazeface"></script>
              <script>
                const video = document.getElementById("video");
                const videoContainer = document.getElementById("video-container");
                let model; // to store the blazeface model
                const canvas = document.getElementById("canvas");
                const nosePoint = document.getElementById("nose-point");
            
                navigator.mediaDevices
                ${
                  cameraDeviceId
                    ? `.getUserMedia({ video: { deviceId: "${cameraDeviceId}" } })`
                    : ".getUserMedia({ video: true })"
                }
                  .then((stream) => {
                    const width = stream.getVideoTracks()[0].getSettings().width;
                    const height = stream.getVideoTracks()[0].getSettings().height;
                    video.srcObject = stream;
                    video.style.width = width;
                    video.style.height = height;
                    canvas.width = width;
                    canvas.height = height;
                    videoContainer.style.width = width + "px";
                    videoContainer.style.height = height + "px";
            
                    const playground = document.createElement("div");
                    const nosePointX = nosePoint.offsetLeft;
                    const nosePointY = nosePoint.offsetTop;
            
                    let matchingCount = 0;
                    const detectFaces = async () => {
                      const prediction = await model.estimateFaces(video, false);
                      // draw the video first
                      // ctx.drawImage(video, 0, 0, width, height);
                      const ctx = canvas.getContext("2d");
                      ctx.clearRect(0, 0, width, height);
                      const keypoints = prediction[0].landmarks;
                      for (let j = 2; j < 3; j++) {
                        const x = keypoints[j][0];
                        const y = keypoints[j][1];
                        ctx.beginPath();
                        ctx.arc(x, y, 3, 0, 2 * Math.PI);
                        ctx.fillStyle = "#0EA5E9";
                        ctx.fill();
                      }
                      if (
                        keypoints[2][0] > nosePointX - 10 &&
                        keypoints[2][0] < nosePointX + 10
                      ) {
                        matchingCount++;
                      } else {
                        matchingCount = 0;
                      }
                      if (matchingCount === 10) {
                        const capture = ctx.drawImage(video, 0, 0, width, height);
                        const base64FaceCapture = canvas.toDataURL("image/png");
                        window.data = {base64FaceCapture};
                        window.close();
                      }
                    };
            
                    // this event is fired when the video is loaded
                    video.addEventListener("loadeddata", async () => {
                      // wait for blazeface model to load
                      model = await blazeface.load();
                      // call the function
                      setInterval(detectFaces, 100);
                    });
                  });
              </script>
            </html>
            `);
        const timer = setInterval(async () => {
          if (liveNessWebcamWindow.closed) {
            clearInterval(timer);
            let liveNessWebcamWindowData = liveNessWebcamWindow.data || {};
            const { base64FaceCapture } = liveNessWebcamWindowData;
            liveNessWebcamWindow = null;
            if (!base64FaceCapture) {
              reject({
                message: "Not enough image to process",
                data: {
                  base64FaceCapture,
                },
              });
            }
            // start request
            // start request
            var method = "POST";
            var path = "/dtis/v2/e-identity/utility/facial/process";

            var date = new Date();
            var amzdate = strftime("%Y%m%dT%H%M%SZ", date);
            var datestamp = strftime("%Y%m%d", date);

            var canonical_uri = path;
            var canonical_querystring = "";
            var canonical_headers =
              "host:" +
              host +
              "\n" +
              "x-amz-date:" +
              amzdate +
              "\n" +
              "x-amz-security-token:" +
              securityToken +
              "\n" +
              "x-api-key:" +
              apikey;

            var signed_headers =
              "host;x-amz-date;x-amz-security-token;x-api-key";

            const availableProcessTypes = [
              "LIVENESS_CHECKING",
              "FACIAL_MATCHING",
              "LIVE_FACIAL_MATCHING_EKYC",
              "LIVE_FACIAL_MATCHING_AUTHENTICATION",
            ];

            const requiredOriginalFrame = availableProcessTypes.filter(
              (item) => item !== "LIVENESS_CHECKING"
            );

            var request_parameters = JSON.stringify({
              process_type: process_type,
              live_frame: handleFixBase64(base64FaceCapture),
              os_type: osType,
              original_frame: requiredOriginalFrame.includes(process_type)
                ? handleFixBase64(originalFrame)
                : undefined,
              lang: lang,
            });

            var payload_hash = await sha256(request_parameters);
            var canonical_request =
              method +
              "\n" +
              canonical_uri +
              "\n" +
              canonical_querystring +
              "\n" +
              canonical_headers +
              "\n\n" +
              signed_headers +
              "\n" +
              payload_hash;

            var algorithm = "AWS4-HMAC-SHA256";
            var credential_scope =
              datestamp + "/" + region + "/" + service + "/" + "aws4_request";
            var hashCanonicalRequest = await sha256(canonical_request);

            var string_to_sign =
              algorithm +
              "\n" +
              amzdate +
              "\n" +
              credential_scope +
              "\n" +
              hashCanonicalRequest.toString();

            var signing_key = getSignatureKey(
              secret_key,
              datestamp,
              region,
              service
            );
            var signature = sign(signing_key, string_to_sign);

            var authorization_header =
              algorithm +
              " " +
              "Credential=" +
              access_key +
              "/" +
              credential_scope +
              ", " +
              "SignedHeaders=" +
              signed_headers +
              ", " +
              "Signature=" +
              signature;
            var headers = {
              "x-amz-date": amzdate,
              Authorization: authorization_header,
              host: host,
              "x-amz-security-token": securityToken,
              "x-api-key": apikey,
            };

            fetch("https://" + host + path, {
              host: host,
              port: 443,
              method: method,
              path: path,
              headers: headers,
              body: request_parameters,
            })
              .then((response) => {
                return response.json();
              })
              .then((data) => {
                resolve(data);
              })
              .catch((err) => {
                reject(err);
              });
          }
        }, 500);
        // });
        // });
      });
    }

    function getMediaSource() {
      return new Promise((resolve, reject) => {
        navigator.mediaDevices.enumerateDevices().then(function (devices) {
          const videoDevices = devices.filter(
            (device) => device.kind === "videoinput"
          );
          resolve(videoDevices);
        }).catch(err => {
          reject(err);
        });
      });
    }

    return {
      getToken: getToken,
      getOCR: getOCR,
      facialProcess: facialProcess,
      getMediaSource: getMediaSource,
    };
  }
}


