// Redirect Worker for the retired PiranhaDB host, api.piranha.bawbel.io.
//
// Why: the hosted API was stopped, but released scanner wheels and older bawbel-mcp
// versions still print or call https://api.piranha.bawbel.io/records/... and cannot be
// changed. This Worker keeps those links working and sends everything else to the
// repository, which explains the status.
//
// Open redirect: not possible. Both destinations are constants. Nothing from the request
// (host, header, or query) chooses where a redirect goes. Only the path and query are
// copied, and only after the fixed origin.

// AVE records are served by the AVE API.
const AVE_API_ORIGIN = "https://api.aveproject.org";
// Everything else lands on the status explanation. 302, so it can move later.
const FALLBACK_URL = "https://github.com/bawbel/piranha-api";

const RECORDS_PATH = "/records";
const STATUS_RECORDS_MOVED = 301;
const STATUS_FALLBACK = 302;

// What: decide where a request to the old host should go.
// Why:  the decision lives in one place, apart from building the Response.
// How:  /records and /records/... keep their path and query on the AVE API (301);
//       every other path gets the fallback (302).
function resolveRedirect(requestUrl) {
  let url;
  try {
    url = new URL(requestUrl);
  } catch {
    return { location: FALLBACK_URL, status: STATUS_FALLBACK };
  }
  const { pathname, search } = url;
  if (pathname === RECORDS_PATH || pathname.startsWith(RECORDS_PATH + "/")) {
    return { location: AVE_API_ORIGIN + pathname + search, status: STATUS_RECORDS_MOVED };
  }
  return { location: FALLBACK_URL, status: STATUS_FALLBACK };
}

// Only the default export, so the file can be pasted into the Cloudflare dashboard as is.
export default {
  async fetch(request) {
    const { location, status } = resolveRedirect(request.url);
    return Response.redirect(location, status);
  },
};
