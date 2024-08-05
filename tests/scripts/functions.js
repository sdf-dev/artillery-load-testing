const cheerio = require('cheerio');

const getAcaCookie = (requestParams, response, context, ee, next) => {
    const cookies = response.headers['set-cookie'];

    if (cookies && cookies.length > 0) {
        let firstCookie = cookies[0];
        if (firstCookie.startsWith('acaAffinity')) {
            const str = firstCookie.split(';')[0];
            let value = str.split('=')[1];
            value = value.split('"').join('');
            context.vars.acaValue = value;
        }
    }
    return next();
};

const getSentinelCookies = (requestParams, response, context, ee, next) => {
    const cookies = response.headers['set-cookie'];
    let sentinelNonce = '';
    let sentinelCorrelation = '';

    if (cookies && cookies.length > 0) {
        let nonceCookie = cookies[0];
        let correlationCookie = cookies[1];

        if (nonceCookie.startsWith('.AspNetCore.OpenIdConnect')) {
            sentinelNonce = nonceCookie.split('=')[1].split(';')[0];
        }

        if (correlationCookie.startsWith('.AspNetCore.Correlation')) {
            sentinelCorrelation = correlationCookie.split('=')[1].split(';')[0];
        }
    }

    context.vars.sentinelNonce = sentinelNonce;
    context.vars.sentinelState = sentinelCorrelation;

    if (response.headers.location) {
        context.vars.sentinelRedirectUrl = response.headers.location;
    } else {
        console.log('Error: No redirect found');
    }
    return next();
}

const getSentinelReturn = (requestParams, response, context, ee, next) => {
    context.vars.sentinelRedirectUrl = response.headers.location;
    context.vars.sentinelLoginUrl = response.headers.location;
    return next();
}

const antiForgeryFunction = (requestParams, response, context, ee, next) => {
    const $ = cheerio.load(response.body);
    const cookies = response.headers['set-cookie'];
    let callBackUrl = '';

    if (cookies && cookies.length > 0) {
        let antiforgeryCookie = cookies[0];

        if (antiforgeryCookie.startsWith('.AspNetCore.Antiforgery')) {
            let antiforgeryValue = antiforgeryCookie.split('=')[1].split(';')[0];
            context.vars.sentinelAntiForgeryValue = antiforgeryValue;
        }
    }

    context.vars.requestVerificationToken = '';
    $('input[name="__RequestVerificationToken"]').each((index, element) => {
        context.vars.requestVerificationToken = $(element).attr('value');
        return false
    });

    callBackUrl = $('input[name="ReturnUrl"]').val();
    context.vars.postReturnUrlParams = callBackUrl
    context.vars.callBackUrl = 'INSERT URL' + callBackUrl
    context.vars.sentinelPostUrl = response.url

    return next();
}

const sentinelPostFunction = (requestParams, response, context, ee, next) => {
    console.log("Making Post Request to Sentinel..")
    return next();
}

const getSuccessfulCallBackFunction = (requestParams, response, context, ee, next) => {
    console.log("Collecting CallBack")
    return next();
}

const checkflowSignIn = (requestParams, response, context, ee, next) => {
    console.log("Making Post request to Checkflow..")
    return next();
}

const endOfTestFunction = (requestParams, response, context, ee, next) => {
    console.log("End of the test")
    return next();
}

module.exports = {
    getAcaCookie: getAcaCookie,
    getSentinelCookies: getSentinelCookies,
    getSentinelReturn: getSentinelReturn,
    sentinelPostFunction: sentinelPostFunction,
    getSuccessfulCallBackFunction: getSuccessfulCallBackFunction,
    antiForgeryFunction: antiForgeryFunction,
    checkflowSignIn: checkflowSignIn,
    endOfTestFunction: endOfTestFunction,
}