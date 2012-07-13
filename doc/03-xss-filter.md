phpsecFilter provides two methods of safely presenting user supplied data on a web page.

The first one is a basic filter (phpsecFilter::f()), and the second one is a bit more advanced (phpsecFilter::t()). phpsecFilter::f() is used to filter a string, while phpsecFilter::t() can be used to create longer texts, using different filters.

phpsecFilter::f() takes two arguments. The first is the string to filter, and the second is the filter to use. There are four filters.

 * **strip:** HTML is stripped from the string before it is inserted.
 * **escapeAll:** HTML and special characters is escaped from the string before it is inserted.
 * **escape:** Only HTML is escaped from the string. Special characters is kept as is *(default)*.
 * **url:** Encode a string according to RFC 3986 for use in a URL.

The following example will strip all HTML from a string.

    echo phpsecFilter::f("this is a string<hr>","strip");

The phpsecFilter::t() method takes two arguments: The first is a base string. The base string is not filtered in any way, but used to glue together one or more unsafe strings. The second argument is a associative array containing the unsafe data, and a key to tell the filter where to place it in the base string. The first character of the key decides what filter to apply to the data.

 * **!key:** HTML and special characters is escaped from the string before it is inserted.
 * **%key:** HTML is stripped from the string before it is inserted.
 * **@key:** Only HTML is escaped from the string. Special characters is kept as is.
 * **&key:** Encode a string according to RFC 3986 for use in a URL.


Example:

    echo phpsecFilter::t(
      "Your search for !query returned !num results.",
      array("!query" => $_POST['q'], "!num" => $numResults)
    );

If $_POST['q'] contains *bogus string&lt;hr&gt;* and $numResults contains *4* the following will be returned from phpsec::f():
`Your search for bogus string &lt;hr&gt; returned 4 results.`

To strip the HTML from the string, use %key.

    echo phpsecFilter::t(
      "Your search for %query returned !num results.",
      array("%query" => $_POST['q'], "!num" => $numResults)
    );

With the same values as the example above this code will return:
`Your search for bogus string returned 4 results.`

Creating safe URLs with phpSec

    echo phpsecFilter::t(
      "http://www.example.com/q=&q",
      array("&q" => "this is a query&amp")
    );

Will output: `http://www.example.com/q=this%20is%20a%20query%2`