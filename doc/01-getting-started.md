Altough phpSec is pretty plug and play there are some small steps you need to take before you are ready to harness the power of phpSec. The first thing is to include phpSec into your application. This is done something like this.

    require_once "phpsec.class.php";

Preparing the data storage if needed
------------------------------------
phpSec saves data in something called *the store*. Everything from session data to cache and one time passwords are saved there. Configuring the store is optional if you only want to use the basic functionality of phpSec. If you don't configure a store the following phpSec modules will be available:
  * phpsecCrypt
  * phpsecFilter
  * phpsecHash (and phpsecPw)
  * phpsecRand
  * phpsecYubikey

If you want full phpSec functionality you need to configure the store. This is done with the static **phpsec::$_dsn** variable. The store is defined as a string with the storage method followed by a colon (:), and the storage destination. So if you want to save your data using flat files to */var/www/phpSec/data* the following example would be correct.

    phpsec::$_dsn = "filesystem:/var/www/phpSec/data";

The target directory needs to be writeable by PHP, and should not be accessible trough your web server.

### Using mySQL for storage ###
*Important:* mySQL for storage is only available in phpSec 0.2-beta and later.

To be able to use mySQL to store all your phpSec data you need PHP with the PDO extension installed. All the latest versions of PHP has this enabled by default, so this should not be a big problem. phpSec only use one table, so we don't need a seperate database, unless you want one.

The following table is needed by phpSec. You can call it whatever you want, but phpsec is probably fine.


    --
    -- Table structure for table `phpsec`
    --
    
    CREATE TABLE IF NOT EXISTS `phpsec` (
      `type` varchar(255) NOT NULL COMMENT &#39;Type of data.&#39;,
      `id` varchar(255) NOT NULL COMMENT &#39;Item ID.&#39;,
      `mac` binary(32) NOT NULL COMMENT &#39;Message Authentication Message.&#39;,
      `time` int(11) unsigned NOT NULL COMMENT &#39;Unix time stamp of creation time.&#39;,
      `data` text NOT NULL COMMENT &#39;Serialized object.&#39;,
      UNIQUE KEY `id` (`id`),
      KEY `type` (`type`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;

After you have created your table you should be all set to configure phpSec to use mySQL.

In order to use mySQL you will need to pass the database connection settings trough the *phpsec::$_dsn* variable.

    <?php
    phpsec::$_dsn = 'mysql:' .
    'dbname=xstore;' .
    'table=phpsec;' .
    'host=localhost;' .
    'username=xstore;' .
    'password=123abc';


The above is an example of how your string may look like. The string consists of several configuration opions and their values. The following options are available and all of them are required. The order is not important.
<table>
	<thead>
		<tr>
			<th scope="col">
				Variable</th>
			<th scope="col">
				Description</th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td>
				dbname</td>
			<td>
				Name of your database.</td>
		</tr>
		<tr>
			<td>
				table</td>
			<td>
				Name of the table. Should be phpsec if you didn&#39;t change it when creating the table.</td>
		</tr>
		<tr>
			<td>
				host</td>
			<td>
				Hostname to your mySQL server. Usually localhost.</td>
		</tr>
		<tr>
			<td>
				username</td>
			<td>
				Your database username.</td>
		</tr>
		<tr>
			<td>
				password</td>
			<td>
				Your database password.</td>
		</tr>
	</tbody>
</table>

Initializing phpSec
-------------------
phpSec is mostly a statically called library, but we still need to initialize some stuff. To do this we call the *phpsec::init()* method.

    phpsec::init();

What this actually does is to prepare the store, make sure that all the files we need are loaded and enables and starts the phpSec session handler. If you want to know more about the session handler, or how to disable it check out the [session handler](/manual/session) page.

Thats it!
---------
Thats it! After the following three lines you should be all set to start using phpSec on your application.

    require_once "phpsec.class.php";
    
    /* Optionally configure the store. */
    phpsec::$_dsn = "filesystem:/var/www/phpSec/data";
    
    phpsec::init();

To learn how to start protecting your application, read on.
