		var input_title = $("#input_title"), input_content = $("#input_content");var tab_counter = 3;function closeDialog() {$('#addTabModal').modal('hide'); };
		function addBtn() {addTab();closeDialog();};
						 
		var $tabs = $(".tabs3").tabs({tabTemplate: "<li><a href='#{href}'>#{label} <span class='ui-icon ui-icon-close'></span></a></li>",
			add: function (event, ui) {
				var tab_content = input_content.val() || "Tab " + tab_counter + " content.";
				$(ui.panel).append("<p>" + tab_content + "</p>");
			},
			show: function(event, ui) {
				$('.tabs3 span.ui-icon').on('click',function() {
					var selected = $tabs.tabs('option', 'selected');
					$tabs.tabs('remove', selected);
					}
				);
			}
		});
									

		function addTab() {var tab_title = input_title.val() || "Tab " + tab_counter;$tabs.tabs("add", "#tabs-" + tab_counter, tab_title);tab_counter++;}

		$(function() {
			var date = new Date();
			var d = date.getDate();
			var m = date.getMonth();
			var y = date.getFullYear();
	
			$('#calendar').fullCalendar({
				header: {
					left: 'prev,next',
					center: 'title',
					right: 'month,basicWeek,basicDay'
				},
				editable: true,
				events: [
					{
						title: 'All day event',
						start: new Date(y, m, 1)
					},
					{
						title: 'Long event',
						start: new Date(y, m, 5),
						end: new Date(y, m, 8)
					},
					{
						id: 999,
						title: 'Repeating event',
						start: new Date(y, m, 2, 16, 0),
						end: new Date(y, m, 3, 18, 0),
						allDay: false
					},
					{
						id: 999,
						title: 'Repeating event',
						start: new Date(y, m, 9, 16, 0),
						end: new Date(y, m, 10, 18, 0),
						allDay: false
					},
					{
						title: 'Actually any color could be applied for background',
						start: new Date(y, m, 30, 10, 30),
						end: new Date(y, m, d+1, 14, 0),
						allDay: false,
						color: '#b55d5c'
					},
					{
						title: 'Lunch',
						start: new Date(y, m, 14, 12, 0),
						end: new Date(y, m, 15, 14, 0),
						allDay: false
					},
					{
						"title": "Birthday PARTY",
						"start": "1359771540",
						"end": "1359773340",
						"allDay": 0
					},
					{
						title: 'Click for Google',
						start: new Date(y, m, 27),
						end: new Date(y, m, 29),
						url: 'http://google.com/'
					}
				]
			});
		});
		$("#post-editor").cleditor({width:        99+'%', height:      250,  });
		$('#tags_1').tagsInput({width: '99%','defaultText': 'add tag',});
		$('a.search-action').click(function() {
			$('.sidebar-search').fadeToggle(150);
		});
    	$(".dropdown-toggle").dropdown();
		$(".sliding_menu").initMenu();
		$(".header a, button, .quick-buttons a, ul.sidebar-actions a, .table-actions a").tooltip();
		$(".chat-box .image a").tooltip();
		$(".tooltips-demo a").tooltip();
		$("a[rel=popover]").popover().click(function(e){e.preventDefault() });
		$(".system_notification").alert();
		$(".chat-entry").autoGrow();
    	$(".tabs, .tabs2").tabs();
		$(".accordion").accordion();
		$("#datepicker").datepicker();
		$("#colorpicker").colorpicker();
		$(".fancybox").fancybox();
		$(".userlist").niceScroll({
			cursorcolor: "#2f2e2e",
			cursoropacitymax: 0.6,
			boxzoom: false,
			touchbehavior: true
		});
		$("#file").customFileInput({
			button_position : 'right'
		});
		$(".sortList").sortable({placeholder: "placeholder"});
		$(".sortList").disableSelection();
		$("#slider_1").slider({
			value: 30,
			orientation: "horizontal",
			range: "min",
			animate: true,
			slide: function(event, ui) {
				$( "#slider_1_value" ).html( "$" + ui.value );
			}
		});
		$("#slider_2").slider({
			values: [15, 65],
			orientation: "horizontal",
			range: true,
			animate: true,
			slide: function(event, ui) {
				$( "#slider_2_value" ).html( "$" + ui.values[ 0 ] + " - $" + ui.values[ 1 ] );
			}            
		});
		$('#file_manager').elfinder({
			url : 'php/connector.php',
		})
		$("#mask_date").mask("99/99/9999");
		$("#mask_phone").mask("99 (999) 999-999-999");
		$("#mask_mobile").mask("(999) 999-9999");
		$("#mask_ccn").mask("9999-9999-9999-9999");
		$("#mask_tin").mask("99-9999999");
		$("#mask_ssn").mask("999-99-9999");
		$("#validation").validationEngine({promptPosition : "topLeft", scroll: true}); 
		$(".checkbox-uniform,.radio-uniform").uniform();
		$(".chzn-select").chosen();
		$(".chzn-select-deselect").chosen({allow_single_deselect: true});
		!function ($) {
			$(function(){
			  window.prettyPrint && prettyPrint()   
			})
		  }(window.jQuery)