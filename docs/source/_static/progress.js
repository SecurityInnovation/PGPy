$(document).ready(function() {
    // iterate over ui-progressbar divs
    $('.ui-progressbar').each(function() {
        var label = $('.progress-label', this);
        var frac = $(label).text().split('/');
        var complete = (parseInt(frac[0]) / parseInt(frac[1])) * 100;

        $(this).progressbar({
            'value': complete
        });

        // finish centering the label
        $(label).css('margin-left', -1 * $(label).width() / 2);
    });
});
