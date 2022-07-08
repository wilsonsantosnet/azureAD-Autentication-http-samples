using BackAD.Native;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;

namespace BackAD.Controllers.Native
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize()]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Get()
        {



            var token = Request.Headers["Authorization"].FirstOrDefault();
            var clearToken = token.Replace("Bearer ", "");
            var tokenRead = new jwtReader().Read(clearToken);
            //var validate = new jwtReader().ValidateToken(clearToken);


            var rng = new Random();
            return Ok(Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray());
        }
    }
}
