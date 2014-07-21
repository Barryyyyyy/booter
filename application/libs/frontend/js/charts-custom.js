				/************************
					Spark Lines
				*************************/
				 $(".sparBars").sparkline('html', {
					type: 'bar', 
					barColor: '#378315', 
					height: '18px'
				});
				 
				 $(".sparBars2").sparkline('html', {
					type: 'bar', 
					barColor: '#156383', 
					height: '18px'
				});
					
					$('.sparBars2').sparkline([4, 1, 5, 7, 9, 9], {
						composite: true,
						fillColor: false,
						lineColor: 'red'
					});
				
				$(".sparBars3").sparkline('html', {
					type: 'bar', 
					barColor: '#838215', 
					height: '18px',
				});
				
				/************************
					Flot Charts
				*************************/
				// Realtime
				$(function () {
					// we use an inline data source in the example, usually data would
					// be fetched from a server
					var data = [], totalPoints = 300;
					function getRandomData() {
						if (data.length > 0)
							data = data.slice(1);
				
						// do a random walk
						while (data.length < totalPoints) {
							var prev = data.length > 0 ? data[data.length - 1] : 50;
							var y = prev + Math.random() * 10 - 5;
							if (y < 0)
								y = 0;
							if (y > 100)
								y = 100;
							data.push(y);
						}
				
						// zip the generated y values with the x values
						var res = [];
						for (var i = 0; i < data.length; ++i)
							res.push([i, data[i]])
						return res;
					}
				
					// setup control widget
					var updateInterval = 30;
					$("#updateInterval").val(updateInterval).change(function () {
						var v = $(this).val();
						if (v && !isNaN(+v)) {
							updateInterval = +v;
							if (updateInterval < 1)
								updateInterval = 1;
							if (updateInterval > 2000)
								updateInterval = 2000;
							$(this).val("" + updateInterval);
						}
					});
				
					// setup plot
					var options = {
						series: { shadowSize: 0, color: '#389abe' }, // drawing is faster without shadows
						yaxis: { min: 0, max: 100 },
						xaxis: { show: false },
						grid: { backgroundColor: 'transparent', borderColor: 'transparent' }
					};
					var plot = $.plot($("#flot-realtime"), [ getRandomData() ], options);
				
					function update() {
						plot.setData([ getRandomData() ]);
						// since the axes don't change, we don't need to call plot.setupGrid()
						plot.draw();
						
						setTimeout(update, updateInterval);
					}
				
					update();
				});
				
				// Various
				$(function () {
					var d1 = [];
					for (var i = 0; i < 14; i += 0.5)
						d1.push([i, Math.sin(i)]);
					
					var d2 = [[0, 3], [4, 8], [8, 5], [9, 13]];
					
					var d3 = [];
					for (var i = 0; i < 14; i += 0.5)
						d3.push([i, Math.cos(i)]);
					
					var d4 = [];
					for (var i = 0; i < 14; i += 0.1)
						d4.push([i, Math.sqrt(i * 10)]);
					
					var d5 = [];
					for (var i = 0; i < 14; i += 0.5)
						d5.push([i, Math.sqrt(i)]);
					
					var d6 = [];
					for (var i = 0; i < 14; i += 0.5 + Math.random())
						d6.push([i, Math.sqrt(2*i + Math.sin(i) + 5)]);
							
					$.plot($("#flot-various"), [
						{
							data: d1,
							lines: { show: true, fill: true }
						},
						{
							data: d2,
							bars: { show: true }
						},
							{
						data: d3,
							points: { show: true }
						},
						{
							data: d4,
							lines: { show: true }
						},
						{
							data: d5,
							lines: { show: true },
							points: { show: true }
						},
						{
							data: d6,
							lines: { show: true, steps: true }
						}
					], {
						grid: { backgroundColor: 'transparent', borderColor: 'transparent' }
					});
				});
				
				// Pie
				$(function () {
					var data = [
						{ label: "Series1",  data: 10},
						{ label: "Series2",  data: 30},
						{ label: "Series3",  data: 90},
						{ label: "Series4",  data: 70}
					];
					
					$.plot($("#flot-pie"), data, {
						series: {
							pie: {
								innerRadius: 0.5,
								show: true
							}
						},
						 legend: {
							show: true
						},
						grid: { backgroundColor: 'transparent', borderColor: 'transparent' }
					});
				});
				
				// Interactive Sin-Cos
				/*
				var series1 = [[0,0], [1,1], [2,2], [3,3], [4,4]], series2 = [[0,4], [1,3], [2,2], [3,1], [4,0]];

				var plot = $.plot($(".chart"),
					   [ { data: series1, label: "sin(x)"}, { data: series2, label: "cos(x)" } ], {
						   series: {
							   lines: { show: true },
							   points: { show: true }
						   },
						   legend: {
								show: true,
								noColumns:2
							},
						   grid: { hoverable: true, clickable: true, borderColor: 'transparent' },
						   yaxis: { min: 0, max: 30, tickDecimals:0 },
						   xaxis: { min: 0, max: 20, tickDecimals:0 }
						 });
			
				function showTooltip(x, y, contents) {
					$('<div id="tooltip" class="tooltip">' + contents + '</div>').css( {
						position: 'absolute',
						display: 'none',
						top: y + 5,
						left: x + 5,
						'z-index': '9999',
						'color': '#fff',
						'font-size': '11px',
						opacity: 0.8
					}).appendTo("body").fadeIn(200);
				}
			
				var previousPoint = null;
				$(".chart").bind("plothover", function (event, pos, item) {
					$("#x").text(pos.x.toFixed(2));
					$("#y").text(pos.y.toFixed(2));
			
					if ($(".chart").length > 0) {
						if (item) {
							if (previousPoint != item.dataIndex) {
								previousPoint = item.dataIndex;
								
								$("#tooltip").remove();
								var x = item.datapoint[0].toFixed(2),
									y = item.datapoint[1].toFixed(2);
								
								showTooltip(item.pageX, item.pageY,
											item.series.label + " of " + x + " = " + y);
							}
						}
						else {
							$("#tooltip").remove();
							previousPoint = null;            
						}
					}
				});
			
				$(".chart").bind("plotclick", function (event, pos, item) {
					if (item) {
						$("#clickdata").text("You clicked point " + item.dataIndex + " in " + item.series.label + ".");
						plot.highlight(item.series, item.datapoint);
					}
				});
				*/
				
				// 2013 (month timestamp, value)
				var d1 = [[1262304000000, 186], [1264982400000, 254], [1267401600000, 270], [1270080000000, 350], [1272672000000, 431], [1275350400000, 526], [1277942400000, 619], [1280620800000, 618], [1283299200000, 822], [1285891200000, 926], [1288569600000, 1068], [1291161600000, 1010]];
				// 2012 (month timestamp, value)
				var d2 = [[1262304000000, 131], [1264982400000, 200], [1267401600000, 320], [1270080000000, 480], [1272672000000, 508], [1275350400000, 628], [1277942400000, 779], [1280620800000, 802], [1283299200000, 908], [1285891200000, 604], [1288569600000, 960], [1291161600000, 1200]];
								 
				var data1 = [
					{label: "2013",  data: d1, points: { symbol: "circle", fillColor: "#058DC7" }, color: '#058DC7'},
					{label: "2012",  data: d2, points: { symbol: "circle", fillColor: "#AA4643" }, color: '#AA4643'}
				];
 
				$.plot($(".chart"), data1, {
					xaxis: {
						min: (new Date(2009, 11, 18)).getTime(),
						max: (new Date(2010, 11, 15)).getTime(),
						mode: "time",
						tickSize: [1, "month"],
						monthNames: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
						// tickLength: 0, // to remove border
						axisLabel: 'Months',
						axisLabelUseCanvas: true,
						axisLabelFontSizePixels: 11,
						axisLabelFontFamily: 'Verdana, Arial, Helvetica, Tahoma, sans-serif',
						axisLabelPadding: 5
					},
					yaxis: {
						axisLabel: 'Revenue (Thousands)',
						axisLabelUseCanvas: true,
						axisLabelFontSizePixels: 11,
						axisLabelFontFamily: 'Verdana, Arial, Helvetica, Tahoma, sans-serif',
						axisLabelPadding: 5
					},
					series: {
						lines: { show: true },
						points: {
							radius: 3,
							show: true,
							fill: true
						},
					},
					grid: {
						hoverable: true,
						borderWidth: 1,
						borderColor: '#d5d5d5'
					},
					legend: {
						labelBoxBorderColor: "none",
						noColumns: 4,
						position: "left"
					}
				});
			 
				function showTooltip(x, y, contents, z) {
					$('<div id="tooltip">' + contents + '</div>').css({
						position: 'absolute',
						display: 'none',
						top: y + 5,
						left: x + 5,
						'z-index': '9999',
						'color': '#fff',
						'font-size': '11px',
						opacity: 0.8,
						'border-color': z,
					}).appendTo("body").fadeIn(200);
				}
			 
				function getMonthName(numericMonth) {
					var monthArray = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
					var alphaMonth = monthArray[numericMonth];
			 
					return alphaMonth;
				}
			 
				function convertToDate(timestamp) {
					var newDate = new Date(timestamp);
					var dateString = newDate.getMonth();
					var monthName = getMonthName(dateString);
			 
					return monthName;
				}
			 
				var previousPoint = null;
			 
				$(".chart").bind("plothover", function (event, pos, item) {
					if (item) {
						if ((previousPoint != item.dataIndex) || (previousLabel != item.series.label)) {
							previousPoint = item.dataIndex;
							previousLabel = item.series.label;
			 
							$("#tooltip").remove();
			 
							var x = convertToDate(item.datapoint[0]),
							y = item.datapoint[1];
							z = item.series.color;
			 
							showTooltip(item.pageX, item.pageY,
								"<b>" + item.series.label + "</b><br /> " + x + " = " + y + "",
								z);
						}
					} else {
						$("#tooltip").remove();
						previousPoint = null;
					}
				});
