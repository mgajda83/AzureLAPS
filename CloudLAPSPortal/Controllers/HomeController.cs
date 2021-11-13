using LAPSPortal.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace LAPSPortal.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> logger;
        private readonly IConfiguration configuration;

        public HomeController(ILogger<HomeController> _logger, IConfiguration _configuration)
        {
            logger = _logger;
            configuration = _configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public async Task<IActionResult> LAPSAsync(string searchValue)
        {
            if (!string.IsNullOrEmpty(searchValue))
            {
                try
                {
                    // Construct new SecretClient with Key Vault uri from appsetting.json using managed system identity of web app
                    string keyVaultUri = configuration.GetSection("KeyVault")["Uri"];

                    LAPSSecret secret = await LAPSSecret.GetComputerAsync(keyVaultUri, searchValue);
                    if (secret != null)
                    {
                        // Construct new Log Analytics wrapper
                        LAPSLogs logClient = new LAPSLogs
                        (
                            workspaceId: configuration.GetSection("LogAnalytics")["WorkspaceId"],
                            sharedKey: configuration.GetSection("LogAnalytics")["SharedKey"],
                            logType: configuration.GetSection("LogAnalytics")["LogType"]
                        );

                        // Construct new audit event
                        LAPSEvent auditEvent = new LAPSEvent()
                        {
                            UserPrincipalName = User.Identity.Name,
                            ComputerName = secret.SecretDeviceName,
                            Action = "LAPSGet",
                            CreatedOn = DateTime.UtcNow,
                            Result = "Success",
                            Id = Convert.ToString(secret.SecretId)
                        };

                        // Send audit event
                        await logClient.SendLogEntry(auditEvent);

                        // Populate view with value from Key Vault
                        ViewData["SecretValue"] = secret.SecretValue;
                        ViewData["SecretDeviceName"] = secret.SecretDeviceName;
                        ViewData["SecretDate"] = secret.SecretDate;
                        ViewData["SecretUserName"] = secret.SecretUserName;
                        ViewData["Result"] = "Success";
                    }
                    else
                    {
                        ViewData["Result"] = "Failed";
                    }
                }
                catch (Exception)
                {
                    ViewData["Result"] = "Failed";
                }
            }

            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
