/**
 * use a GET param to determine what the endpoint should *actually* be doing
 * this is important since 'recursive' type flows/logic are going on and server
 * is *always* getting invoked at the same URL (whatever is defined in the
 * proxy).  However the forwarded response contains appropriate headers etc
 * that allows us to detect what is *really* going on.
 */
const HANDLER_INDICATOR_PARAM_NAME = "__oeas_handler__";

const DEFAULT_COOKIE_NAME = "_oeas_session";
const STATE_CSRF_COOKIE_NAME = "_oeas_csrf";
const STATE_CSRF_COOKIE_EXPIRY = "43200"; //12 hours
const DEFAULT_CLIENT_CLOCK_TOLERANCE = 5;
const SESSION_CACHE_PREFIX = "session:";
const ISSUER_CACHE_DURATION = 43200 * 1000;
const CLIENT_CACHE_DURATION = 43200 * 1000;

module.exports = {
  DEFAULT_CLIENT_CLOCK_TOLERANCE,
  DEFAULT_COOKIE_NAME,
  STATE_CSRF_COOKIE_NAME,
  STATE_CSRF_COOKIE_EXPIRY,
  HANDLER_INDICATOR_PARAM_NAME,
  SESSION_CACHE_PREFIX,
  ISSUER_CACHE_DURATION,
  CLIENT_CACHE_DURATION
};
