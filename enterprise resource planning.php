<?php
/**
 * 
namespace FacturaScripts\Core\App;

use FacturaScripts\Core\Base\DataBase;
use FacturaScripts\Core\Base\MiniLog;
use FacturaScripts\Core\Base\PluginManager;
use FacturaScripts\Core\Base\TelemetryManager;
use FacturaScripts\Core\Base\ToolBox;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * App class is used for encapsulate common parts of code for the normal App execution.
 *
 * @author Carlos García Gómez <carlos@facturascripts.com>
 */
abstract class App
{

    /**
     * Database access manager.
     *
     * @var DataBase
     */
    protected $dataBase;

    /**
     * Plugin manager.
     *
     * @var PluginManager
     */
    protected $pluginManager;

    /**
     * Gives us access to the HTTP request parameters.
     *
     * @var Request
     */
    protected $request;

    /**
     * HTTP response object.
     *
     * @var Response
     */
    protected $response;

    /**
     * Requested Uri
     *
     * @var string
     */
    protected $uri;

    abstract protected function die(int $status, string $message = '');

    /**
     * Initializes the app.
     *
     * @param string $uri
     */
    public function __construct(string $uri = '/')
    {
        $this->request = Request::createFromGlobals();
        if ($this->request->cookies->get('fsLang')) {
            ToolBox::i18n()->setDefaultLang($this->request->cookies->get('fsLang'));
        }

        $this->dataBase = new DataBase();
        $this->pluginManager = new PluginManager();
        $this->response = new Response();
        $this->uri = $uri;

        // timezone
        date_default_timezone_set(FS_TIMEZONE);

        // add security headers
        $this->response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $this->response->headers->set('X-XSS-Protection', '1; mode=block');
        $this->response->headers->set('X-Content-Type-Options', 'nosniff');
        $this->response->headers->set('Strict-Transport-Security', 'max-age=31536000');

        ToolBox::log()->debug('URI: ' . $this->uri);
        ToolBox::log()::setContext('uri', $this->uri);
    }

    /**
     * Connects to the database and loads the configuration.
     *
     * @return bool
     */
    public function connect(): bool
    {
        if ($this->dataBase->connect()) {
            ToolBox::appSettings()->load();
            $this->loadPlugins();
            return true;
        }

        return false;
    }

    /**
     * Save log and disconnects from the database.
     */
    public function close()
    {
        // send telemetry (if configured)
        $telemetry = new TelemetryManager();
        $telemetry->update();

        // save log
        MiniLog::save();

        $this->dataBase->close();
    }

    /**
     * Returns the data into the standard output.
     */
    public function render()
    {
        $this->response->send();
    }

    /**
     * Runs the application core.
     *
     * @return bool
     */
    public function run(): bool
    {
        if (false === $this->dataBase->connected()) {
            ToolBox::i18nLog()->critical('cant-connect-database');
            $this->die(Response::HTTP_INTERNAL_SERVER_ERROR);
            return false;
        } elseif ($this->isIPBanned()) {
            ToolBox::i18nLog()->critical('ip-banned');
            $this->die(Response::HTTP_TOO_MANY_REQUESTS);
            return false;
        }

        return true;
    }
// Loop all controllers in /Dinamic/Lib/API
foreach (scandir(FS_FOLDER . DIRECTORY_SEPARATOR . 'Dinamic' . DIRECTORY_SEPARATOR . 'Lib' . DIRECTORY_SEPARATOR . 'API', SCANDIR_SORT_NONE) as $resource) {
    if (substr($resource, -4) !== '.php') {
        continue;
    }

    // The name of the class will be the same as that of the file without the php extension.
    // Classes will be descendants of Base/APIResourceClass.
    $class = substr('\\FacturaScripts\\Dinamic\\Lib\\API\\' . $resource, 0, -4);
    $APIClass = new $class($this->response, $this->request, []);
    if (isset($APIClass) && method_exists($APIClass, 'getResources')) {
    /**
     * Returns param number $num in uri.
     *
     * @param string $num
     *
     * @return string
     */
    protected function getUriParam(string $num): string
    {
        $params = explode('/', substr($this->uri, 1));
        return $params[$num] ?? '';
    }

    /**
     * Add or increase the attempt counter of the current client IP address.
     */
    protected function ipWarning()
    {
        $ipFilter = ToolBox::ipFilter();
        $ipFilter->setAttempt($ipFilter->getClientIp());
    }

    /**
     * Returns true if the client IP has been banned.
     *
     * @return bool
     */
    protected function isIPBanned(): bool
    {
        $ipFilter = ToolBox::ipFilter();
        return $ipFilter->isBanned($ipFilter->getClientIp());
    }

    /**
     * Initialize plugins.
     */
    private function loadPlugins()
    {
        foreach ($this->pluginManager->enabledPlugins() as $pluginName) {
            $initClass = '\\FacturaScripts\\Plugins\\' . $pluginName . '\\Init';
            if (class_exists($initClass)) {
                $initObject = new $initClass();
                $initObject->init();
            }
        }
    }
}
// Returns an ordered array with all available resources.
$finalResources = array_merge(...$resources);
ksort($finalResources);
return $finalResources;
}

/**
* Returns true if the token has the requested access to the resource.
*
* @return bool
*/
private function isAllowed(): bool
{
$resource = $this->getUriParam(2);
if ($resource === '' || $this->apiKey->fullaccess) {
    return true;
}

$apiAccess = new ApiAccess();
$where = [
    new DataBaseWhere('idapikey', $this->apiKey->id),
    new DataBaseWhere('resource', $resource)
];
if ($apiAccess->loadFromCode('', $where)) {
    switch ($this->request->getMethod()) {
        case 'DELETE':
            return $apiAccess->allowdelete;

        case 'GET':
            return $apiAccess->allowget;

        case 'PATCH':
        case 'PUT':
            return $apiAccess->allowput;

        case 'POST':
            return $apiAccess->allowpost;
    }
}

return false;
}

/**
* Check if API is disabled. API can't be disabled if FS_API_KEY is defined
* in the config.php file.
*
* @return bool
*/
private function isDisabled(): bool
{
// Is FS_API_KEY defined in the config?
if (defined('FS_API_KEY')) {
    return false;
}

return ToolBox::appSettings()->get('default', 'enable_api', false) == false;
}

/**
* Selects the resource
*
* @return bool
*/
private function selectResource(): bool
{
$map = $this->getResourcesMap();

$resourceName = $this->getUriParam(2);
if ($resourceName === '') {
    // If no command, expose resources and exit
    $this->exposeResources($map);
    return true;
}

if (!isset($map[$resourceName]['API'])) {
    $this->die(Response::HTTP_BAD_REQUEST, 'invalid-resource');
    return false;
}

// get params
$param = 3;
$params = [];
while (($item = $this->getUriParam($param)) !== '') {
    $params[] = $item;
    $param++;
}

try {
    $APIClass = new $map[$resourceName]['API']($this->response, $this->request, $params);
    return $APIClass->processResource($map[$resourceName]['Name']);
} catch (Exception $exc) {
    ToolBox::log()->critical('API-ERROR: ' . $exc->getMessage());
    $this->die(Response::HTTP_INTERNAL_SERVER_ERROR);
}

return false;
}

/**
* Selects the API version if it is supported
*
* @return bool
*/
private function selectVersion(): bool
{
if ($this->getUriParam(1) == self::API_VERSION) {
    return $this->selectResource();
}

$this->die(Response::HTTP_NOT_FOUND, 'api-version-not-found');
return true;
}
}
